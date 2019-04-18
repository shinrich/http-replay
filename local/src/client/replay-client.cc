#include "core/ArgParser.h"
#include "core/HttpReplay.h"
#include "swoc/bwf_ex.h"
#include "swoc/bwf_ip.h"
#include "swoc/bwf_std.h"

#include <assert.h>
#include <chrono>
#include <list>
#include <mutex>
#include <sys/time.h>
#include <thread>
#include <unistd.h>

#include <dirent.h>
#include <fcntl.h>
#include <netinet/tcp.h>
#include <sys/socket.h>

namespace swoc {
inline BufferWriter &bwformat(BufferWriter &w, bwf::Spec const &spec,
                              std::chrono::milliseconds ms) {
  return bwformat(w, spec, ms.count()).write("ms");
}
} // namespace swoc

using swoc::TextView;

struct Txn {
  HttpHeader _req; ///< Request to send.
  HttpHeader _rsp; ///< Response to expect.
};

struct Ssn {
  std::list<Txn> _txn;
  std::string _path;
  unsigned _line_no = 0;
  uint64_t _start; ///< Start time in HR ticks.
  bool is_tls = false;
};
std::mutex LoadMutex;

std::list<Ssn *> Session_List;

std::deque<swoc::IPEndpoint> Target, Target_Https;

bool Proxy_Mode = false;

class ClientReplayFileHandler : public ReplayFileHandler {
  swoc::Errata file_open(swoc::file::path const &path);
  swoc::Errata ssn_open(YAML::Node const &node) override;
  swoc::Errata txn_open(YAML::Node const &node) override;
  swoc::Errata client_request(YAML::Node const &node) override;
  swoc::Errata proxy_request(YAML::Node const &node) override;
  swoc::Errata server_response(YAML::Node const &node) override;
  swoc::Errata proxy_response(YAML::Node const &node) override;
  swoc::Errata txn_close() override;
  swoc::Errata ssn_close() override;

  void txn_reset();
  void ssn_reset();

  std::string _path;
  Ssn *_ssn;
  Txn _txn;
};

bool Shutdown_Flag = false;

class ClientThreadInfo : public ThreadInfo {
public:
  Ssn *_ssn = nullptr;
  bool data_ready() override {
    return Shutdown_Flag ? true : this->_ssn != nullptr;
  }
};

class ClientThreadPool : public ThreadPool {
public:
  std::thread make_thread(std::thread *t) override;
};

ClientThreadPool Client_Thread_Pool;

void TF_Client(std::thread *t);

std::thread ClientThreadPool::make_thread(std::thread *t) {
  return std::thread(
      TF_Client, t); // move the temporary into the list element for permanence.
}

swoc::Errata ClientReplayFileHandler::file_open(swoc::file::path const &path) {
  _path = path.string();
  return {};
}

void ClientReplayFileHandler::ssn_reset() { _ssn = nullptr; }

void ClientReplayFileHandler::txn_reset() {
  _txn.~Txn();
  new (&_txn) Txn;
}

swoc::Errata ClientReplayFileHandler::ssn_open(YAML::Node const &node) {
  static constexpr TextView TLS_PREFIX{"tls"};
  swoc::Errata errata;
  _ssn = new Ssn();
  _ssn->_path = _path;
  _ssn->_line_no = node.Mark().line;

  if (node[YAML_SSN_PROTOCOL_KEY]) {
    auto proto_node{node[YAML_SSN_PROTOCOL_KEY]};
    if (proto_node.IsSequence()) {
      for (auto const &n : proto_node) {
        if (TextView{n.Scalar()}.starts_with_nocase(TLS_PREFIX)) {
          _ssn->is_tls = true;
          break;
        }
      }
    } else {
      errata.warn(
          R"(Session at "{}":{} has a value for "{}" that is not a sequence..)",
          _path, _ssn->_line_no, YAML_SSN_PROTOCOL_KEY);
    }
  } else {
    errata.info(R"(Session at "{}":{} has no "{}" key.)", _path, _ssn->_line_no,
                YAML_SSN_PROTOCOL_KEY);
  }

  if (node[YAML_SSN_START_KEY]) {
    auto start_node{node[YAML_SSN_START_KEY]};
    if (start_node.IsScalar()) {
      auto t = swoc::svtou(start_node.Scalar());
      if (t != 0) {
        _ssn->_start = t / 1000; // Convert to usec from nsec
      } else {
        errata.warn(
            R"(Session at "{}":{} has a "{}" value "{}" that is not a positive integer.)",
            _path, _ssn->_line_no, YAML_SSN_START_KEY, start_node.Scalar());
      }
    } else {
      errata.warn(R"(Session at "{}":{} has a "{}" key that is not a scalar.)",
                  _path, _ssn->_line_no, YAML_SSN_START_KEY);
    }
  }

  return errata;
}

swoc::Errata ClientReplayFileHandler::txn_open(YAML::Node const &) {
  LoadMutex.lock();
  return {};
}

swoc::Errata ClientReplayFileHandler::client_request(YAML::Node const &node) {
  if (!Proxy_Mode) {
    return _txn._req.load(node);
  }
  return {};
}

swoc::Errata ClientReplayFileHandler::proxy_request(YAML::Node const &node) {
  if (Proxy_Mode) {
    return _txn._req.load(node);
  }
  return {};
}

swoc::Errata ClientReplayFileHandler::proxy_response(YAML::Node const &node) {
  if (!Proxy_Mode) {
    return _txn._rsp.load(node);
  }
  return {};
}

swoc::Errata ClientReplayFileHandler::server_response(YAML::Node const &node) {
  if (Proxy_Mode) {
    return _txn._rsp.load(node);
  }
  return {};
}

swoc::Errata ClientReplayFileHandler::txn_close() {
  _ssn->_txn.emplace_back(std::move(_txn));
  LoadMutex.unlock();
  return {};
}

swoc::Errata ClientReplayFileHandler::ssn_close() {
  {
    std::lock_guard<std::mutex> lock(LoadMutex);
    Session_List.push_back(_ssn);
  }
  this->ssn_reset();
  return {};
}

swoc::Errata Run_Transaction(Stream &stream, Txn const &txn) {
  Info("Running transaction.");
  swoc::Errata errata{txn._req.transmit(stream)};
  if (errata.is_ok()) {
    HttpHeader rsp_hdr;
    swoc::LocalBufferWriter<MAX_HDR_SIZE> w;
    Info("Reading response header.");
    auto read_result{rsp_hdr.read_header(stream, w)};
    if (read_result.is_ok()) {
      ssize_t body_offset{read_result};
      auto result{rsp_hdr.parse_response(TextView(w.data(), body_offset))};
      if (result.is_ok()) {
        Info("Reading response body.");
        rsp_hdr.update_content_length();
        rsp_hdr.update_transfer_encoding();
        errata = rsp_hdr.drain_body(stream, w.view().substr(body_offset));
      } else {
        errata.error(R"(Invalid response.)");
        errata.note(result);
      }
    } else {
      errata.note(read_result);
    }
  }
  return errata;
}

swoc::Errata do_connect(Stream *stream, const swoc::IPEndpoint *real_target) {
  swoc::Errata errata;
  int socket_fd = socket(real_target->family(), SOCK_STREAM, 0);
  if (0 <= socket_fd) { 
    int ONE = 1;
    struct linger l;
    l.l_onoff  = 0;
    l.l_linger = 0;
    setsockopt(socket_fd, SOL_SOCKET, SO_LINGER, (char *)&l, sizeof(l));
    if (setsockopt(socket_fd, SOL_SOCKET, SO_REUSEADDR, &ONE, sizeof(int)) < 0) {
      errata.error(R"(Could not set reuseaddr on socket {} - {}.)", socket_fd,
                     swoc::bwf::Errno{});
    } else {
      errata = stream->open(socket_fd);
      if (errata.is_ok()) {
        if (0 == connect(socket_fd, &real_target->sa, real_target->size())) {
          static const int ONE = 1;
          setsockopt(socket_fd, IPPROTO_TCP, TCP_NODELAY, &ONE, sizeof(ONE));
          errata = stream->connect();
        } else {
          errata.error(R"(Failed to connect socket - {})", swoc::bwf::Errno{});
        }
      } else {
        errata.error(R"(Failed to open stream - {})", swoc::bwf::Errno{});
      }  
    }
  } else {
    errata.error(R"(Failed to open socket - {})", swoc::bwf::Errno{});
  }
  return errata;
}

swoc::Errata Run_Session(Ssn const &ssn, swoc::IPEndpoint const &target,
                         swoc::IPEndpoint const &target_https) {
  swoc::Errata errata;
  std::unique_ptr<Stream> stream;
  const swoc::IPEndpoint *real_target;

  Info(R"(Starting session "{}":{}.)", ssn._path, ssn._line_no);

  if (ssn.is_tls) {
    stream.reset(new TLSStream());
    real_target = &target_https;
  } else {
    stream.reset(new Stream());
    real_target = &target;
  }

  Info("Connecting.");
  errata = do_connect(stream.get(), real_target);
  if (errata.is_ok()) {
    for (auto const &txn : ssn._txn) {
      if (stream->is_closed()) {
        errata = do_connect(stream.get(), real_target);
      }
      if (errata.is_ok()) {
        errata = Run_Transaction(*stream, txn);
      } else {
        break;
      }
    }
  }
  return std::move(errata);
}

void TF_Client(std::thread *t) {
  ClientThreadInfo info;
  info._thread = t;
  int target_index = 0;
  int target_https_index = 0;
  
  while (!Shutdown_Flag) {
    swoc::Errata errata;
    info._ssn = nullptr;
    Client_Thread_Pool.wait_for_work(&info);

    if (info._ssn != nullptr) {
      swoc::Errata result = Run_Session(*info._ssn, Target[target_index], Target_Https[target_https_index]);
      if (!result.is_ok()) {
        std::cerr << result;
      }
      if (++target_index >= Target.size()) target_index = 0;
      if (++target_https_index >= Target_Https.size()) target_https_index = 0;
    }
  }
}
bool session_start_compare(const Ssn *ssn1, const Ssn *ssn2) {
  return ssn1->_start < ssn2->_start;
}

/** Command execution.
 *
 * This handles parsing and acting on the command line arguments.
 */
struct Engine {
  ts::ArgParser parser;    ///< Command line argument parser.
  ts::Arguments arguments; ///< Results from argument parsing.

  static constexpr swoc::TextView COMMAND_RUN{"run"};
  static constexpr swoc::TextView COMMAND_RUN_ARGS{
      "Arguments:\n\t<dir>: Directory containing replay files.\n\t<upstream http>: hostname and port for http requests. Can be a comma seprated list\n\t<upstream https>: hostname and port for https requests.  Can be a comma separated list "};
  void command_run();

  /// Status code to return to the operating system.
  int status_code = 0;
  /// Error reporting.
  swoc::Errata erratum;
};

uint64_t GetUTimestamp() {
  auto retval = std::chrono::duration_cast<std::chrono::microseconds>(
      std::chrono::system_clock::now().time_since_epoch());
  return retval.count();
}

void Engine::command_run() {
  auto args{arguments.get("run")};
  dirent **elements = nullptr;

  if (args.size() < 3) {
    erratum.error(R"(Not enough arguments for "{}" command.\n{})", COMMAND_RUN,
                  COMMAND_RUN_ARGS);
    status_code = 1;
    return;
  }

  if (arguments.get("--no-proxy")) {
    Proxy_Mode = true;
  }

  erratum =resolve_ips(args[1], Target);
  if (!erratum.is_ok()) {
    return;
  }
  erratum =resolve_ips(args[2], Target_Https);
  if (!erratum.is_ok()) {
    return;
  }

  Info(R"(Loading directory "{}".)", args[0]);
  auto result =
      Load_Replay_Directory(swoc::file::path{args[0]},
                            [](swoc::file::path const &file) -> swoc::Errata {
                              ClientReplayFileHandler handler;
                              return Load_Replay_File(file, handler);
                            },
                            10);
  if (!result.is_ok() && result.severity() != swoc::Severity::ERROR) {
    return;
  }

  Info(R"(Initialize TLS)");
  TLSStream::init();

  // Sort the Session_List and adjust the time offsets
  Session_List.sort(session_start_compare);

  // After this, any string expected to be localized that isn't is an error,
  // so lock down the local string storage to avoid locking and report an
  // error instead if not found.
  HttpHeader::_frozen = true;
  size_t max_content_length = 0;
  uint64_t offset_time = 0;
  int transaction_count = 0;
  if (!Session_List.empty()) {
    offset_time = Session_List.front()->_start;
  }
  for (auto *ssn : Session_List) {
    ssn->_start -= offset_time;
    transaction_count += ssn->_txn.size();
    for (auto const &txn : ssn->_txn) {
      max_content_length =
          std::max<size_t>(max_content_length, txn._req._content_size);
    }
  }
  HttpHeader::set_max_content_length(max_content_length);

  float rate_multiplier = 0.0;
  auto rate_arg{arguments.get("rate")};
  auto repeat_arg{arguments.get("repeat")};
  auto sleep_limit_arg{arguments.get("sleep-limit")};
  int repeat_count;
  uint64_t sleep_limit = 500000;
  if (rate_arg.size() == 1 && !Session_List.empty()) {
    int target = atoi(rate_arg[0].c_str());
    if (target == 0.0) {
      rate_multiplier = 0.0;
    } else {
      rate_multiplier = (transaction_count * 1000000.0) /
                        (target * Session_List.back()->_start);
    }
  }
  std::cout << "Rate multiplier is " << rate_multiplier
            << " Transaction count is " << transaction_count << " Time delta "
            << Session_List.back()->_start << " first time " << offset_time
            << "\n";

  if (repeat_arg.size() == 1) {
    repeat_count = atoi(repeat_arg[0].c_str());
  } else {
    repeat_count = 1;
  }

  if (sleep_limit_arg.size() == 1) {
    sleep_limit = atoi(sleep_limit_arg[0].c_str());
  }

  auto start = std::chrono::high_resolution_clock::now();
  unsigned n_ssn = 0;
  unsigned n_txn = 0;
  for (int i = 0; i < repeat_count; i++) {
    uint64_t firsttime = GetUTimestamp();
    uint64_t lasttime = GetUTimestamp();
    uint64_t nexttime;
    for (auto *ssn : Session_List) {
      uint64_t curtime = GetUTimestamp();
      nexttime = (uint64_t)(rate_multiplier * ssn->_start) + firsttime;
      if (nexttime > curtime) {
        // std::cout << "Sleep " << nexttime - curtime << " ms " << nexttime <<
        // " " << curtime << " " << (uint64_t)(rate_multiplier*ssn->_start) +
        // lasttime << "\n";
        usleep(std::min(sleep_limit, nexttime - curtime));
      }
      lasttime = GetUTimestamp();
      ClientThreadInfo *tinfo =
          dynamic_cast<ClientThreadInfo *>(Client_Thread_Pool.get_worker());
      if (nullptr == tinfo) {
        std::cerr << "Failed to get worker thread\n";
      } else {
        // Only pointer to worker thread info.
        {
          std::unique_lock<std::mutex> lock(tinfo->_mutex);
          tinfo->_ssn = ssn;
          tinfo->_cvar.notify_one();
        }
      }
      ++n_ssn;
      n_txn += ssn->_txn.size();
    }
  }
  // Wait until all threads are done
  Shutdown_Flag = true;
  Client_Thread_Pool.join_threads();

  auto delta = std::chrono::duration_cast<std::chrono::milliseconds>(
      std::chrono::high_resolution_clock::now() - start);
  erratum.info("{} transactions in {} sessions (reuse {:.2f}) in {} ({:.3f} / "
               "millisecond).",
               n_txn, n_ssn, n_txn / static_cast<double>(n_ssn), delta,
               n_txn / static_cast<double>(delta.count()));
};

int main(int argc, const char *argv[]) {
  Engine engine;

  engine.parser.add_option("--verbose", "", "Enable verbose output")
      .add_option("--version", "-V", "Print version string")
      .add_option("--help", "-h", "Print usage information");

  engine.parser
      .add_command(Engine::COMMAND_RUN.data(), Engine::COMMAND_RUN_ARGS.data(),
                   "", MORE_THAN_ONE_ARG_N,
                   [&]() -> void { engine.command_run(); })
      .add_option("--no-proxy", "", "Use proxy data instead of client data.")
      .add_option("--repeat", "", "Repeatedly replay data set", "", 1, "")
      .add_option(
          "--sleep-limit", "",
          "Limit the amount of time spent sleeping between replays (ms)", "", 1,
          "")
      .add_option("--rate", "", "Specify desired transacton rate", "", 1, "");

  // parse the arguments
  engine.arguments = engine.parser.parse(argv);

  if (auto args{engine.arguments.get("verbose")}; args) {
    Verbose = true;
  }

  engine.arguments.invoke();

  if (!engine.erratum.is_ok()) {
    std::cerr << engine.erratum;
  } else if (engine.erratum.count()) {
    std::cout << engine.erratum;
  }

  return engine.status_code;
}

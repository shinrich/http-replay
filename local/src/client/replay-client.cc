#include "core/ArgParser.h"
#include "core/HttpReplay.h"
#include "swoc/bwf_ex.h"
#include "swoc/bwf_ip.h"

#include <chrono>
#include <list>
#include <mutex>
#include <thread>
#include <unistd.h>
#include <sys/time.h>

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

swoc::IPEndpoint Target, Target_Https;

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

class ClientThreadInfo : public ThreadInfo {
public:
  Ssn *_ssn = nullptr;
  bool data_ready() override {
    return this->_ssn;
  }
};

class ClientThreadPool : public ThreadPool {
public:
  std::thread make_thread(std::thread *t) override;
};

ClientThreadPool Client_Thread_Pool;

bool Shutdown_Flag = false;

void TF_Client(std::thread *t);

std::thread ClientThreadPool::make_thread(std::thread *t) {
  return std::thread(TF_Client, t); // move the temporary into the list element for permanence.
}

swoc::Errata ClientReplayFileHandler::file_open(swoc::file::path const &path) {
  _path = path.string();
  return {};
}

void ClientReplayFileHandler::ssn_reset() {
  _ssn = nullptr;
}

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
        _ssn->_start = t/1000; // Convert to usec from nsec
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
    errata = stream->open(socket_fd);
    if (errata.is_ok()) {
      if (0 == connect(socket_fd, &real_target->sa, real_target->size())) {
        static const int ONE = 1;
        setsockopt(socket_fd, IPPROTO_TCP, TCP_NODELAY, &ONE, sizeof(ONE));
        errata = stream->connect();
      } else {
        errata.error(R"(Failed to connect socket - {})", swoc::bwf::Errno{});
      }
    }
    else {
      errata.error(R"(Failed to open stream - {})", swoc::bwf::Errno{});
    }  
  } else {
    errata.error(R"(Failed to open socket - {})", swoc::bwf::Errno{});
  }
  return errata;
}

swoc::Errata Run_Session(Ssn const &ssn, swoc::IPEndpoint const &target, swoc::IPEndpoint const &target_https) {
  swoc::Errata errata;
  int socket_fd = -2;
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
  if (0 <= socket_fd) {
    close(socket_fd);
  }
  return std::move(errata);
}

void TF_Client(std::thread *t) {
  ClientThreadInfo info;
  info._thread = t;
  while (!Shutdown_Flag) {
    swoc::Errata errata;
    info._ssn = nullptr;
    Client_Thread_Pool.wait_for_work(&info);

    if (info._ssn != nullptr) {
        swoc::Errata result = Run_Session(*info._ssn, Target, Target_Https);
        if (!result.is_ok()) {
          std::cerr << result;
        }
    }
  }  
}
bool session_start_compare(const Ssn *ssn1, const Ssn *ssn2) 
{
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
      "Arguments:\n\t<dir>: Directory containing replay files.\n\t<upstream>: "
      "Upstream destination for http requests."
      "Upstream destination for https requests."};
  void command_run();

  /// Status code to return to the operating system.
  int status_code = 0;
  /// Error reporting.
  swoc::Errata erratum;
};

uint64_t GetUTimestamp() {
  struct timeval tv;
  gettimeofday(&tv, nullptr);
  return tv.tv_sec*1000000 + tv.tv_usec;
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


  auto &&[tmp_target, result_http] = Resolve_FQDN(args[1]);
  if (!result_http.is_ok()) {
    return;
  }
  Target = tmp_target;
  auto &&[tmp_target_https, result_https] = Resolve_FQDN(args[2]);
  if (!result_https.is_ok()) {
    return;
  }
  Target_Https = tmp_target_https;

  Info(R"(Loading directory "{}".)", args[0]);
  auto result =
      Load_Replay_Directory(swoc::file::path{args[0]},
                            [](swoc::file::path const &file) -> swoc::Errata {
                              ClientReplayFileHandler handler;
                              return Load_Replay_File(file, handler);
                            },
                            10);
  if (!result.is_ok()) {
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
  if (rate_arg.size() == 1 && !Session_List.empty()) {
    int target = atoi(rate_arg[0].c_str());
    rate_multiplier = (transaction_count * 1000000000.0)/(target*Session_List.back()->_start);
  }
  std::cout << "Rate multiplier is " << rate_multiplier << " Transaction count is " << transaction_count << " Time delta " << Session_List.back()->_start << " first time " << offset_time << "\n";

  auto start = std::chrono::high_resolution_clock::now();
  unsigned n_ssn = 0;
  unsigned n_txn = 0;
  uint64_t lasttime = GetUTimestamp();
  for (auto *ssn : Session_List) {
    uint64_t curtime = GetUTimestamp();
    uint64_t nexttime = rate_multiplier * ssn->_start + lasttime;
    if (nexttime > curtime) {
      //std::cout << "Sleep " << nexttime - curtime << " ms " << nexttime << " " << curtime << "\n";
      //usleep(nexttime - curtime);
    }
    lasttime = GetUTimestamp();
    ClientThreadInfo *tinfo = dynamic_cast<ClientThreadInfo *>(Client_Thread_Pool.get_worker());
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
/*
    result = Run_Session(*ssn, target, target_https);
    if (!result.is_ok()) {
      std::cerr << result;
      break;
    }
    if (result.count() && Verbose) {
      std::cout << result;
    }
*/
    ++n_ssn;
    n_txn += ssn->_txn.size();
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

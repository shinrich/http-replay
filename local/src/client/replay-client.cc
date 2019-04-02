#include <dirent.h>

#include <list>
#include <mutex>
#include <thread>
#include <unistd.h>

#include "core/ArgParser.h"
#include "core/HttpReplay.h"
#include "swoc/bwf_ex.h"

using swoc::TextView;

struct Txn {
  HttpHeader _req; ///< Request to send.
  HttpHeader _rsp; ///< Response to expect.
};

using Session = std::list<Txn>;
std::mutex LoadMutex;

std::list<Session> Session_List;

bool Proxy_Mode = false;

class ClientReplayFileHandler : public ReplayFileHandler {
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

  Session _ssn;
  Txn _txn;
};

void ClientReplayFileHandler::ssn_reset() {
  _ssn.~Session();
  new (&_ssn) Session;
}

void ClientReplayFileHandler::txn_reset() {
  _txn.~Txn();
  new (&_txn) Txn;
}

swoc::Errata ClientReplayFileHandler::ssn_open(YAML::Node const &) {
  return {};
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
  _ssn.emplace_back(std::move(_txn));
  LoadMutex.unlock();
  return {};
}

swoc::Errata ClientReplayFileHandler::ssn_close() {
  {
    std::lock_guard<std::mutex> lock(LoadMutex);
    Session_List.emplace_back(std::move(_ssn));
  }
  this->ssn_reset();
  return {};
}

swoc::Errata Run_Transaction(int fd, Txn const &txn, bool &eos_p) {
  swoc::Errata errata{txn._req.transmit(fd)};
  if (errata.is_ok()) {
    size_t eoh_offset = 0;
    HttpHeader rsp_hdr;
    swoc::LocalBufferWriter<MAX_RSP_HDR_SIZE> w;
    while (w.remaining() > 0) {
      auto n = read(fd, w.aux_data(), w.remaining());
      if (n > 0) {
        size_t start =
            std::max<size_t>(w.size(), HTTP_EOH.size()) - HTTP_EOH.size();
        w.commit(n);
        size_t offset = w.view().substr(start).find(HTTP_EOH);
        if (TextView::npos != offset) {
          eoh_offset = start + offset + HTTP_EOH.size();
          break;
        }
      } else if (EINTR != errno) {
        errata.error(
            R"(Connection closed unexpectedly while waiting for response header - {}.)",
            swoc::bwf::Errno{});
        break;
      }
    }

    if (eoh_offset) {
      auto result{rsp_hdr.parse_response(w.view().substr(0, eoh_offset))};
      if (result.is_ok()) {
        size_t left_overs = w.size() - eoh_offset;
        // soak up content.
        std::string buff;
        size_t content_length = std::numeric_limits<size_t>::max();
        if (auto spot{rsp_hdr._fields.find(HttpHeader::FIELD_CONTENT_LENGTH)};
            spot != rsp_hdr._fields.end()) {
          content_length = swoc::svtou(spot->second);
          if (content_length < left_overs) {
            errata.error(
                R"(Response overrun - received {} bytes of content, expected {}.)",
                left_overs, content_length);
            return errata;
          }
          content_length -= left_overs;
        }
        buff.reserve(std::min<size_t>(content_length, MAX_DRAIN_BUFFER_SIZE));

        size_t body_size = 0;
        while (body_size < content_length) {
          size_t n =
              read(fd, buff.data(),
                   std::min(content_length - body_size, MAX_DRAIN_BUFFER_SIZE));
          if (n <= 0) {
            if (content_length != std::numeric_limits<size_t>::max()) {
              errata.error(
                  R"(Response underrun - recieved {} bytes of content, expected {}, when file closed because {}.)",
                  body_size, content_length, swoc::bwf::Errno{});
            }
            eos_p = true;
            break;
          }
          body_size += n;
        }
      } else {
        errata.error(R"(Invalid response.)");
        errata.note(result);
      }
    } else {
      errata.error(R"(Response exceeded maximum size {}.)", MAX_RSP_HDR_SIZE);
    }
  }
  return errata;
}

swoc::Errata Run_Session(Session const &ssn, swoc::IPEndpoint const &target) {
  swoc::Errata errata;

  int socket_fd = socket(target.family(), SOCK_STREAM, 0);
  if (socket_fd >= 0) {
    int connect_result = connect(socket_fd, &target.sa, target.size());
    if (0 == connect_result) {
      bool eos_p = false; // end of stream during a transaction.
      for (auto const &txn : ssn) {
        if (eos_p) {
          errata.error(
              R"(Session closed before all transactions were processed.)");
          break;
        }
        errata = Run_Transaction(socket_fd, txn, eos_p);
        if (!errata.is_ok()) {
          close(socket_fd);
          break;
        }
      }
    } else {
      errata.error(R"(Failed to connect to {} - {}.)", target,
                   swoc::bwf::Errno{});
    }
  } else {
    errata.error(R"(Failed to open socket - {})", swoc::bwf::Errno{});
  }
  return std::move(errata);
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
      "Upstream destination for requests."};
  void command_run();

  /// Status code to return to the operating system.
  int status_code = 0;
  /// Error reporting.
  swoc::Errata erratum;
};

void Engine::command_run() {
  auto args{arguments.get("run")};
  dirent **elements = nullptr;

  if (args.size() < 2) {
    erratum.error(R"(Not enough arguments for "{}" command.\n{})", COMMAND_RUN,
                  COMMAND_RUN_ARGS);
    status_code = 1;
    return;
  }

  if (arguments.get("--no-proxy")) {
    Proxy_Mode = true;
  }

  auto &&[target, target_result] = Resolve_FQDN(args[1]);
  if (!target_result.is_ok()) {
    std::cerr << target_result;
    return;
  }

  std::cout << "Loading " << args[0] << std::endl;
  auto result =
      Load_Replay_Directory(swoc::file::path{args[0]},
                            [](swoc::file::path const &file) -> swoc::Errata {
                              ClientReplayFileHandler handler;
                              return Load_Replay_File(file, handler);
                            },
                            10);
  if (!result.is_ok()) {
    std::cerr << result;
    return;
  }

  for (auto const &ssn : Session_List) {
    result = Run_Session(ssn, target);
    if (!result.is_ok()) {
      std::cerr << result;
    }
  }
};

int main(int argc, const char *argv[]) {
  Engine engine;

  engine.parser.add_option("--debug", "", "Enable debugging output")
      .add_option("--version", "-V", "Print version string")
      .add_option("--help", "-h", "Print usage information");

  engine.parser
      .add_command(Engine::COMMAND_RUN.data(), Engine::COMMAND_RUN_ARGS.data(),
                   "", MORE_THAN_ONE_ARG_N,
                   [&]() -> void { engine.command_run(); })
      .add_option("--no-proxy", "", "Use proxy data instead of client data.");

  // parse the arguments
  engine.arguments = engine.parser.parse(argv);

  engine.arguments.invoke();

  if (!engine.erratum.is_ok()) {
    std::cerr << engine.erratum;
  }
  std::cout << "Ready" << std::endl;
  return engine.status_code;
}

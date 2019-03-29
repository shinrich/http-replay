#include <dirent.h>

#include <list>
#include <mutex>
#include <thread>
#include <unistd.h>

#include "core/ArgParser.h"
#include "core/HttpReplay.h"
#include "swoc/bwf_ex.h"

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

  swoc::Errata handle_request(YAML::Node const &node, HttpHeader &hdr);
  swoc::Errata handle_response(YAML::Node const &node, HttpHeader &hdr);
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

swoc::Errata ClientReplayFileHandler::handle_request(YAML::Node const &node,
                                                     HttpHeader &hdr) {
  swoc::Errata errata;

  if (node[YAML_HDR_KEY]) {
    auto proxy_hdr_node{node[YAML_HDR_KEY]};
    if (proxy_hdr_node[YAML_FIELDS_KEY]) {
      auto proxy_field_list_node{proxy_hdr_node[YAML_FIELDS_KEY]};
      auto result{hdr.parse_fields(proxy_field_list_node)};
      if (!result.is_ok()) {
        errata.error("Failed to parse request at {}", node.Mark());
        errata.note(result);
      }
    }
  }
  return errata;
}

swoc::Errata ClientReplayFileHandler::client_request(YAML::Node const &node) {
  if (!Proxy_Mode) {
    return this->handle_request(node, _txn._req);
  }
  return {};
}

swoc::Errata ClientReplayFileHandler::proxy_request(YAML::Node const &node) {
  if (Proxy_Mode) {
    return this->handle_request(node, _txn._req);
  }
  return {};
}

swoc::Errata ClientReplayFileHandler::handle_response(YAML::Node const &node,
                                                      HttpHeader &hdr) {
  swoc::Errata errata;

  if (node[YAML_HDR_KEY]) {
    auto hdr_node{node[YAML_HDR_KEY]};
    if (hdr_node[YAML_FIELDS_KEY]) {
      auto field_list_node{hdr_node[YAML_FIELDS_KEY]};
      auto result{hdr.parse_fields(field_list_node)};
      if (!result.is_ok()) {
        errata.error("Failed to parse response at {}", node.Mark());
        errata.note(result);
      }
    }
  }

  return errata;
}

swoc::Errata ClientReplayFileHandler::proxy_response(YAML::Node const &node) {
  if (!Proxy_Mode) {
    return this->handle_response(node, _txn._rsp);
  }
  return {};
}

swoc::Errata ClientReplayFileHandler::server_response(YAML::Node const &node) {
  if (Proxy_Mode) {
    return this->handle_response(node, _txn._rsp);
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

swoc::Errata Run_Transaction(int fd, Txn const &txn) {
  auto result = txn._req.transmit(fd);
}

swoc::Errata Run_Session(Session const &ssn, swoc::IPEndpoint const &target) {
  swoc::Errata errata;

  int socket_fd = socket(target.family(), SOCK_STREAM, 0);
  if (socket_fd >= 0) {
    int connect_result = connect(socket_fd, &target.sa, target.size());
    if (0 == connect_result) {
      for (auto const &txn : ssn) {
        Run_Transaction(socket_fd, txn);
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

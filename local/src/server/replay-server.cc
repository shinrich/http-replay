#include <array>
#include <atomic>
#include <csignal>
#include <cstring>
#include <mutex>
#include <thread>
#include <unordered_map>
#include <unordered_set>

#include <bits/signum.h>
#include <dirent.h>
#include <netinet/in.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <unistd.h>

#include "core/ArgParser.h"
#include "core/HttpReplay.h"
#include "swoc/BufferWriter.h"
#include "swoc/Errata.h"
#include "swoc/MemArena.h"
#include "swoc/TextView.h"
#include "swoc/bwf_base.h"
#include "swoc/bwf_ex.h"
#include "swoc/bwf_ip.h"
#include "swoc/swoc_file.h"
#include "swoc/swoc_ip.h"
#include "yaml-cpp/yaml.h"

using swoc::BufferWriter;
using swoc::TextView;

/** Command execution.
 *
 * This handles parsing and acting on the command line arguments.
 */
struct Engine {
  ts::ArgParser parser;    ///< Command line argument parser.
  ts::Arguments arguments; ///< Results from argument parsing.

  void command_run();

  /// Status code to return to the operating system.
  int status_code = 0;
  /// Error reporting.
  swoc::Errata errata;
};

bool Shutdown_Flag = false;

std::mutex LoadMutex;

struct Txn {
  HttpHeader _req;
  HttpHeader _rsp;
};

std::unordered_map<std::string, Txn, std::hash<std::string_view>> Transactions;

class ServerReplayFileHandler : public ReplayFileHandler {
  swoc::Errata txn_open(YAML::Node const &node) override;
  swoc::Errata proxy_request(YAML::Node const &node) override;
  swoc::Errata server_response(YAML::Node const &node) override;
  swoc::Errata txn_close() override;

  void reset();

  std::string _key;
  Txn _txn;
};

void ServerReplayFileHandler::reset() {
  _txn.~Txn();
  new (&_txn) Txn;
}

swoc::Errata ServerReplayFileHandler::txn_open(YAML::Node const &) {
  LoadMutex.lock();
  return {};
}

swoc::Errata ServerReplayFileHandler::proxy_request(YAML::Node const &node) {
  swoc::Errata errata = _txn._req.load(node);
  if (errata.is_ok()) {
    _key = _txn._req.make_key();
  }
  return errata;
}

swoc::Errata ServerReplayFileHandler::server_response(YAML::Node const &node) {
  auto errata{_txn._rsp.load(node)};
  if (errata.is_ok()) {
    if (auto spot{_txn._rsp._fields.find(HttpHeader::FIELD_CONTENT_LENGTH)};
        spot != _txn._rsp._fields.end()) {
      TextView src{spot->second}, parsed;
      auto cl = swoc::svtou(src, &parsed);
      if (parsed.size() == src.size()) {
        if (_txn._rsp._content_size != cl) {
          errata.info(
              R"(Overriding content size () with "{}" header value {} at {}.)",
              _txn._rsp._content_size, HttpHeader::FIELD_CONTENT_LENGTH, cl,
              node.Mark());
          _txn._rsp._content_size = cl;
        }
      } else {
        errata.info(R"(Invalid "{}" field at {} - not a positive integer.)",
                    HttpHeader::FIELD_CONTENT_LENGTH, node.Mark());
      }
    }
  }
  return errata;
}

swoc::Errata ServerReplayFileHandler::txn_close() {
  Transactions[_key] = std::move(_txn);
  LoadMutex.unlock();
  this->reset();
  return {};
}

void TF_Serve(Stream &stream) {
  swoc::Errata errata;
  bool done_p = false;
  while (!stream.is_closed() && errata.is_ok()) {
    HttpHeader req_hdr;
    swoc::LocalBufferWriter<MAX_HDR_SIZE> w;
    auto read_result{req_hdr.read_header(stream, w)};

    if (read_result.is_ok()) {
      ssize_t body_offset = read_result;
      if (0 == body_offset) {
        break; // client closed between transactions, that's not an error.
      }
      auto result{
          req_hdr.parse_request(swoc::TextView(w.data(), body_offset))};
      if (result.is_ok()) {
        Info("Handling request");
        auto key{req_hdr.make_key()};
        auto spot{Transactions.find(key)};
        if (spot != Transactions.end()) {
          [[maybe_unused]] auto const &[key, txn] = *spot;
          req_hdr.update_content_length();
          req_hdr.update_transfer_encoding();
          if (req_hdr._content_length_p || req_hdr._chunked_p) {
            Info("Draining request body.");
            errata =
                req_hdr.drain_body(stream, w.view().substr(body_offset));
          }
          Info("Responding to request - status {}.", txn._rsp._status);
          errata = txn._rsp.transmit(stream);
        } else {
          errata.error(R"(Proxy request with key "{}" not found.)", key);
        }
      } else {
        errata.error(R"(Proxy request was malformed.)");
        errata.note(result);
      }
    } else {
      errata.note(read_result);
      break;
    }
  }

  if (!errata.is_ok()) {
    std::cerr << errata;
  }
}

void TF_Accept(int socket_fd) {
  Stream reader;
  while (!Shutdown_Flag) {
    swoc::Errata errata;
    swoc::IPEndpoint remote_addr;
    socklen_t remote_addr_size;
    int fd =
        accept4(socket_fd, &remote_addr.sa, &remote_addr_size, SOCK_NONBLOCK);
    if (fd >= 0) {
      errata = reader.open(fd);
      if (errata.is_ok()) {
        static const int ONE = 1;
        setsockopt(socket_fd, IPPROTO_TCP, TCP_NODELAY, &ONE, sizeof(ONE));
        TF_Serve(reader);
      } else {
        std::cerr << errata;
      }
    }
  }
}

void Engine::command_run() {
  auto args{arguments.get("run")};
  swoc::IPEndpoint server_addr;
  auto server_addr_arg{arguments.get("listen")};
  swoc::LocalBufferWriter<1024> w;

  if (args.size() < 1) {
    errata.error(
        R"("run" command requires a directory path as an argument.)");
  }

  if (server_addr_arg) {
    if (server_addr_arg.size() == 1) {
      if (!server_addr.parse(server_addr_arg[0])) {
        errata.error(R"("{}" is not a valid IP address.)", server_addr_arg);
        return;
      }
    } else {
      errata.error(
          R"(--listen option must have a single value, the listen address and port.)");
    }
  }

  if (!errata.is_ok()) {
    return;
  }

  errata =
      Load_Replay_Directory(swoc::file::path{args[0]},
                            [](swoc::file::path const &file) -> swoc::Errata {
                              ServerReplayFileHandler handler;
                              return Load_Replay_File(file, handler);
                            },
                            10);

  if (!errata.is_ok()) {
    return;
  }
  if (errata.count()) {
    std::cout << errata;
    errata.clear();
  }

  // After this, any string expected to be localized that isn't is an error,
  // so lock down the local string storage to avoid locking and report an
  // error instead if not found.
  HttpHeader::_frozen = true;
  size_t max_content_length = 0;
  for (auto const &[key, txn] : Transactions) {
    max_content_length =
        std::max<size_t>(max_content_length, txn._rsp._content_size);
  }
  HttpHeader::set_max_content_length(max_content_length);

  std::cout << "Ready" << std::endl;

  // Set up listen port.
  int socket_fd = socket(server_addr.family(), SOCK_STREAM, 0);
  if (socket_fd >= 0) {
    int bind_result = bind(socket_fd, &server_addr.sa, server_addr.size());
    if (bind_result == 0) {
      int listen_result = listen(socket_fd, 1);
      if (listen_result == 0) {
        Info(R"(Listening at {})", server_addr);
        std::thread runner{TF_Accept, socket_fd};
        runner.join();
      } else {
        errata.error(R"(Could not listen to {} - {}.)", server_addr,
                     swoc::bwf::Errno{});
      }
    } else {
      errata.error(R"(Could not bind to {} - {}.)", server_addr,
                   swoc::bwf::Errno{});
    }
  } else {
    errata.error(R"(Could not create socket - {}.)", swoc::bwf::Errno{});
  }
  if (socket_fd >= 0) {
    close(socket_fd);
  }
}

int main(int argc, const char *argv[]) {
  Engine engine;

  engine.parser.add_option("--verbose", "", "Enable verbose output")
      .add_option("--version", "-V", "Print version string")
      .add_option("--help", "-h", "Print usage information");

  engine.parser
      .add_command("run", "run <dir>: the replay server using data in <dir>",
                   "", 1, [&]() -> void { engine.command_run(); })
      .add_option("--listen", "", "Listen address and port", "", 1,
                  "127.0.0.1:8080");

  // parse the arguments
  engine.arguments = engine.parser.parse(argv);
  if (auto args{engine.arguments.get("verbose")}; args) {
    Verbose = true;
  }

  engine.arguments.invoke();

  if (!engine.errata.is_ok()) {
    std::cerr << engine.errata;
  }
  return engine.status_code;
}

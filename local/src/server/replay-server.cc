#include <array>
#include <atomic>
#include <cstring>
#include <mutex>
#include <thread>
#include <unordered_map>
#include <unordered_set>

#include <dirent.h>
#include <netinet/in.h>
#include <sys/socket.h>
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

std::unordered_map<std::string, HttpHeader, std::hash<std::string_view>>
    Transactions;

class ServerReplayFileHandler : public ReplayFileHandler {
  swoc::Errata txn_open(YAML::Node const &node) override;
  swoc::Errata proxy_request(YAML::Node const &node) override;
  swoc::Errata server_response(YAML::Node const &node) override;
  swoc::Errata txn_close() override;

  void reset();

  std::string key;
  HttpHeader server_hdr;
};

void ServerReplayFileHandler::reset() {
  server_hdr.~HttpHeader();
  new (&server_hdr) HttpHeader;
}

swoc::Errata ServerReplayFileHandler::txn_open(YAML::Node const &) {
  LoadMutex.lock();
  return {};
}

swoc::Errata ServerReplayFileHandler::proxy_request(YAML::Node const &node) {
  HttpHeader hdr;
  swoc::Errata errata = hdr.load(node);
  if (errata.is_ok()) {
    key = hdr.make_key();
  }
  return errata;
}

swoc::Errata ServerReplayFileHandler::server_response(YAML::Node const &node) {
  return server_hdr.load(node);
}

swoc::Errata ServerReplayFileHandler::txn_close() {
  Transactions[key] = std::move(server_hdr);
  LoadMutex.unlock();
  this->reset();
  return {};
}

void TF_Serve(int socket_fd) {
  swoc::LocalBufferWriter<MAX_RSP_HDR_SIZE> w;
  bool done_p = false;
  while (!done_p) {
    HttpHeader req_hdr;
    swoc::Errata errata;
    ssize_t n;
    w.clear();
    while (w.remaining() > 0) {
      n = read(socket_fd, w.aux_data(), w.remaining());
      if (n >= 0) {
        size_t offset =
            std::max<size_t>(w.size(), HTTP_EOH.size()) - HTTP_EOH.size();
        w.commit(n);
        if (TextView::npos == w.view().substr(offset).find(HTTP_EOH)) {
          continue;
        }
        auto result{req_hdr.parse_request(w.view())};
        if (result.is_ok()) {
          auto key{req_hdr.make_key()};
          auto spot{Transactions.find(key)};
          if (spot != Transactions.end()) {
            spot->second.transmit(socket_fd);
          } else {
            errata.error(R"(Proxy request with key "{}" not found.)", key);
          }
        } else {
          errata.error(R"(Proxy request was malformed.)");
          errata.note(result);
          done_p = true;
          break;
        }
      } else {
        if (errno != EINTR) {
          done_p = true;
          break;
        }
      }
    }
    if (!errata.is_ok()) {
      std::cerr << errata;
    }
  }
  close(socket_fd);
}

void TF_Accept(int socket_fd) {
  swoc::LocalBufferWriter<MAX_RSP_HDR_SIZE> w;
  while (!Shutdown_Flag) {
    swoc::Errata errata;
    swoc::IPEndpoint remote_addr;
    socklen_t remote_addr_size;
    int fd = accept(socket_fd, &remote_addr.sa, &remote_addr_size);
    if (fd >= 0) {
      TF_Serve(fd);
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

  Load_Replay_Directory(swoc::file::path{args[0]},
                        [](swoc::file::path const &file) -> swoc::Errata {
                          ServerReplayFileHandler handler;
                          return Load_Replay_File(file, handler);
                        },
                        10);

  // After this, any string expected to be localized that isn't is an error,
  // so lock down the local string storage to avoid locking and report an
  // error instead if not found.
  HttpHeader::_frozen = true;
  size_t max_content_length = 0;
  for (auto const &[key, value] : Transactions) {
    max_content_length =
        std::max<size_t>(max_content_length, value._content_size);
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
        w.print(R"(Listening at {})", server_addr);
        std::cout << w.view() << std::endl;

        std::thread runner{TF_Accept, socket_fd};
        runner.join();
      } else {
        errata.error(R"(Could not listen to {} - {}.)", server_addr,
                     swoc::bwf::Errno{listen_result});
      }
    } else {
      errata.error(R"(Could not bind to {} - {}.)", server_addr,
                   swoc::bwf::Errno{bind_result});
    }
  } else {
    errata.error(R"(Could not create socket - {}.)", swoc::bwf::Errno{});
  }
}

int main(int argc, const char *argv[]) {
  Engine engine;

  engine.parser.add_option("--debug", "", "Enable debugging output")
      .add_option("--version", "-V", "Print version string")
      .add_option("--help", "-h", "Print usage information");

  engine.parser
      .add_command("run", "run <dir>: the replay server using data in <dir>",
                   "", 1, [&]() -> void { engine.command_run(); })
      .add_option("--listen", "", "Listen address and port", "", 1,
                  "127.0.0.1:8080");

  // parse the arguments
  engine.arguments = engine.parser.parse(argv);

  engine.arguments.invoke();

  if (!engine.errata.is_ok()) {
    std::cerr << engine.errata;
  }
  return engine.status_code;
}

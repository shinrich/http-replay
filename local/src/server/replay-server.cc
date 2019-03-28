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
  swoc::Errata erratum;
};

bool Shutdown_Flag = false;

std::mutex LoadMutex;

std::unordered_map<std::string, HttpHeader, std::hash<std::string_view>>
    Transactions;

void TF_Load_Session(std::atomic<int> *global_idx, int n, dirent **elements) {
  int idx;
  while ((idx = (*global_idx)++) < n) {
    swoc::file::path path{elements[idx]->d_name};
    swoc::Errata erratum;
    std::error_code ec;
    std::cout << "Loading [" << idx << "] " << path.c_str() << std::endl;
    std::string content{swoc::file::load(path, ec)};
    if (ec.value()) {
      std::cerr << "Error: " << ec.message() << std::endl;
    } else {
      try {
        auto root{YAML::Load(content)};
        std::lock_guard<std::mutex> lock(LoadMutex);

        if (root[YAML_SSN_KEY]) {
          auto ssn_list_node{root[YAML_SSN_KEY]};
          if (ssn_list_node.IsSequence()) {
            for (auto const &ssn_node : ssn_list_node) {
              if (ssn_node[YAML_TXN_KEY]) {
                auto txn_list_node{ssn_node[YAML_TXN_KEY]};
                if (txn_list_node.IsSequence()) {
                  for (auto const &txn_node : txn_list_node) {
                    std::string key;
                    HttpHeader server_txn;

                    if (txn_node[YAML_PROXY_REQ_KEY]) {
                      auto proxy_req_node{txn_node[YAML_PROXY_REQ_KEY]};
                      if (proxy_req_node[YAML_HDR_KEY]) {
                        auto proxy_hdr_node{proxy_req_node[YAML_HDR_KEY]};
                        if (proxy_hdr_node[YAML_FIELDS_KEY]) {
                          auto proxy_field_list_node{
                              proxy_hdr_node[YAML_FIELDS_KEY]};
                          HttpHeader proxy_txn;
                          auto result{
                              proxy_txn.parse_fields(proxy_field_list_node)};
                          if (result.is_ok()) {
                            key = proxy_txn.make_key(_key_format);
                          } else {
                            erratum.error("Failed to parse proxy request at {}",
                                          proxy_req_node.Mark());
                            erratum.note(result);
                          }
                        }
                      }
                    }

                    if (txn_node[YAML_SERVER_RSP_KEY]) {
                      auto response_node{txn_node[YAML_SERVER_RSP_KEY]};
                      if (response_node[YAML_HDR_KEY]) {
                        auto hdr_node{response_node[YAML_HDR_KEY]};
                        if (hdr_node[YAML_FIELDS_KEY]) {
                          auto field_list_node{hdr_node[YAML_FIELDS_KEY]};
                          auto result{server_txn.parse_fields(field_list_node)};
                          if (!result.is_ok()) {
                            erratum.error(
                                "Failed to parse server response at {}",
                                response_node.Mark());
                            erratum.note(result);
                          }
                        }
                      }
                    }

                    if (erratum.is_ok()) {
                      Transactions[key] = std::move(server_txn);
                    } else {
                      std::cerr << erratum;
                    }
                  }
                }
              }
            }
          } else {
            erratum.error(R"("{}" value at {} is not a sequence.)",
                          YAML_SSN_KEY, ssn_list_node.Mark());
          }
        } else {
          erratum.error(R"(Failed to parse "{}".)", path.c_str());
        }
      } catch (std::exception const &ex) {
        erratum.error("Exception: {}", ex.what());
      }
    }
    if (!erratum.is_ok()) {
      std::cerr << erratum;
    }
  }
}

void TF_Server(int socket_fd) {
  static constexpr TextView TERMINATOR{"\r\n\r\n"};
  swoc::LocalBufferWriter<MAX_RSP_HDR_SIZE> w;
  while (!Shutdown_Flag) {
    swoc::Errata erratum;
    swoc::IPEndpoint remote_addr;
    socklen_t remote_addr_size;
    int fd = accept(socket_fd, &remote_addr.sa, &remote_addr_size);
    if (fd >= 0) {
      ssize_t n;
      w.clear();
      while (w.remaining() > 0) {
        n = read(fd, w.aux_data(), w.remaining());
        if (n >= 0) {
          w.commit(n);
          if (swoc::TextView::npos != w.view().rfind("\r\n\r\n")) {
            HttpHeader proxy_req;
            if (Parse_Request(w.view(), proxy_req)) {
              auto key{proxy_req.make_key(_key_format)};
              auto spot{Transactions.find(key)};
              if (spot != Transactions.end()) {
                spot->second.transmit(fd);
                close(fd);
              } else {
                erratum.error(R"(Proxy request with key "{}" not found.)", key);
              }
            } else {
              erratum.error(R"(Proxy request was malformed.)");
            }
          }
        } else if (n < 0) {
          break;
        }
      }
    }
    if (!erratum.is_ok()) {
      std::cerr << erratum;
    }
  }
}

void Engine::command_run() {
  swoc::IPEndpoint server_addr;
  auto server_addr_arg{arguments.get("listen")};
  swoc::LocalBufferWriter<1024> w;

  if (server_addr_arg) {
    if (server_addr_arg.size() == 1) {
      if (!server_addr.parse(server_addr_arg[0])) {
        erratum.error(R"("{}" is not a valid IP address.)", server_addr_arg);
        return;
      }
    } else {
      erratum.error(
          R"(--listen option must have a single value, the listen address and port.)");
    }
  }

  dirent **elements = nullptr;
  auto base_path{arguments.get("run")[0]};

  if (0 == chdir(base_path.data())) {
    int n_sessions =
        scandir(".", &elements,
                [](const dirent *entry) -> int {
                  return 0 == strcasecmp(swoc::TextView{entry->d_name,
                                                        strlen(entry->d_name)}
                                             .suffix_at('.'),
                                         "json")
                             ? 1
                             : 0;
                },
                &alphasort);
    std::cout << "Loading " << n_sessions << " session files" << std::endl;

    std::array<std::thread, 10> threads;
    std::atomic_int idx{0};
    for (int x = 0; x < std::tuple_size<decltype(threads)>::value; ++x) {
      threads[x] = std::thread(TF_Load_Session, &idx, n_sessions, elements);
    }

    for (int x = 0; x < std::tuple_size<decltype(threads)>::value; ++x) {
      threads[x].join();
    }

    // After this, any string expected to be localized that isn't is an error,
    // so lock down the local string storage to avoid locking and report an
    // error instead if not found.
    HttpHeader::_frozen = true;

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

          std::thread runner{TF_Server, socket_fd};
          runner.join();
        } else {
          erratum.error(R"(Could not listen to {} - {}.)", server_addr,
                        swoc::bwf::Errno{listen_result});
        }
      } else {
        erratum.error(R"(Could not bind to {} - {}.)", server_addr,
                      swoc::bwf::Errno{bind_result});
      }
    } else {
      erratum.error(R"(Could not create socket - {}.)", swoc::bwf::Errno{});
    }
  } else {
    erratum.error(R"(Could not access directory "{}" - {}.)", base_path,
                  swoc::bwf::Errno{});
  }
};

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

  if (!engine.erratum.is_ok()) {
    std::cerr << engine.erratum;
  }
  return engine.status_code;
}

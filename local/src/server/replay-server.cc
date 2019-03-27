#include <array>
#include <atomic>
#include <thread>
#include <cstring>
#include <unordered_map>
#include <unordered_set>
#include <mutex>

#include <unistd.h>
#include <dirent.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include "yaml-cpp/yaml.h"
#include "tscore/ArgParser.h"
#include "swoc/TextView.h"
#include "swoc/swoc_file.h"
#include "swoc/MemArena.h"
#include "swoc/BufferWriter.h"
#include "swoc/bwf_base.h"
#include "swoc/Errata.h"
#include "swoc/swoc_ip.h"

using swoc::BufferWriter;
using swoc::TextView;

static constexpr size_t MAX_REQ_HDR_SIZE = 65536;
static constexpr size_t MAX_RSP_HDR_SIZE = 65536;

static const std::string YAML_SSN_KEY{"sessions"};
static const std::string YAML_TXN_KEY{"transactions"};
static const std::string YAML_PROXY_REQ_KEY{"proxy-request"};
static const std::string YAML_SERVER_RSP_KEY{"server-response"};
static const std::string YAML_HDR_KEY{"headers"};
static const std::string YAML_FIELDS_KEY{"fields"};

namespace swoc {
BufferWriter &
bwformat(BufferWriter &w, bwf::Spec const &spec, YAML::Mark const &mark) {
  return w.print("line {}", mark.line);
}
} // namespace swoc

/** Command execution.
 *
 * This handles parsing and acting on the command line arguments.
 */
struct Engine {
  ts::ArgParser parser; ///< Command line argument parser.
  ts::Arguments arguments; ///< Results from argument parsing.

  void command_run();

  /// Status code to return to the operating system.
  int status_code = 0;
  /// Error reporting.
  swoc::Errata erratum;
};

TextView Key_Format{"{field.uid}"};

std::unordered_set<swoc::TextView, std::hash<std::string_view>> Local_Strings;
swoc::MemArena Local_String_Storage;
bool Local_String_Storage_Frozen = false;

std::mutex LoadMutex;

swoc::Rv<TextView> Localize(TextView text) {
  auto spot = Local_Strings.find(text);
  if (spot != Local_Strings.end()) {
    return *spot;
  } else if (!Local_String_Storage_Frozen) {
    auto span{Local_String_Storage.alloc(text.size()).rebind<char>()};
    memcpy(span.data(), text.data(), text.size());
    return TextView{span.data(), text.size()};
  } else {
    swoc::Errata erratum;
    erratum.error(R"(Non-localized string "{}")", text);
    return {{}, std::move(erratum)};
  }
}

class Transaction;

class Binding : public swoc::bwf::ContextNames<const Transaction> {
public:
protected:
  /** Override of virtual method to provide an implementation.
   *
   * @param w Output.
   * @param spec Format specifier for output.
   * @return @a w
   *
   * This is called from the formatting logic to generate output for a named specifier. Subclasses
   * that need to handle name dispatch differently need only override this method.
   */
  BufferWriter &operator()(BufferWriter &w, const swoc::bwf::Spec &spec) const override;
};

class Transaction {
  using Fields = std::unordered_map<swoc::TextView, std::string, std::hash<std::string_view>>;
public:
  void transmit(int fd);

  swoc::Errata parse_fields(YAML::Node const &field_list_node);

  std::string make_key(TextView fmt);

  unsigned _status;
  unsigned _content_size = 0;
  Fields _fields;
  Binding _binding;
};

void Transaction::transmit(int fd) {
  swoc::LocalBufferWriter<MAX_RSP_HDR_SIZE> w;
  w.print("200 OK\r\n");
  for (auto const&[name, value] : _fields) {
    w.write(name).write(": ").write(value).write("\r\n");
  }
  w.write("\r\n");
  write(fd, w.data(), w.size());
}

swoc::Errata Transaction::parse_fields(YAML::Node const &field_list_node) {
  swoc::Errata erratum;

  for (auto const &field_node : field_list_node) {
    if (field_node.IsSequence()) {
      if (field_node.size() == 2) {
        auto name{Localize(field_node[0].Scalar())};
        TextView value{field_node[1].Scalar()};
        if (name.is_ok()) {
          _fields[name] = value;
        } else {
          erratum.error("Unexpected field name.");
          erratum.note(name.errata());
          break;
        }
      } else {
        erratum.error("Field at {} is not a sequence of length 2 as required.", field_node.Mark());
      }
    } else {
      erratum.error("Field at {} is not a sequence as required.", field_node.Mark());
    }
  }
  return erratum;
}

std::string Transaction::make_key(TextView fmt) {
  swoc::FixedBufferWriter w{nullptr};
  std::string key;
  w.print_n(_binding.bind(*this), fmt);
  key.resize(w.extent());
  swoc::FixedBufferWriter{key.data(), key.size()}.print_n(_binding.bind(*this), fmt);
  return std::move(key);
};

std::unordered_map<swoc::TextView, Transaction, std::hash<std::string_view>> Transactions;

BufferWriter &Binding::operator()(BufferWriter &w, const swoc::bwf::Spec &spec) const {
  static constexpr TextView FIELD_PREFIX{"field."};
  TextView name{spec._name};
  if (name.starts_with_nocase(FIELD_PREFIX)) {
    name.remove_prefix(FIELD_PREFIX.size());
    if (auto spot{_ctx->_fields.find(name)}; spot != _ctx->_fields.end()) {
      bwformat(w, spec, spot->second);
    } else {
      bwformat(w, spec, "*N/A*");
    }
  } else {
    bwformat(w, spec, "*N/A*");
  }
  return w;
}

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
                    Transaction server_txn;

                    if (txn_node[YAML_PROXY_REQ_KEY]) {
                      auto proxy_req_node{txn_node[YAML_PROXY_REQ_KEY]};
                      if (proxy_req_node[YAML_HDR_KEY]) {
                        auto proxy_hdr_node{proxy_req_node[YAML_HDR_KEY]};
                        if (proxy_hdr_node[YAML_FIELDS_KEY]) {
                          auto proxy_field_list_node{proxy_hdr_node[YAML_FIELDS_KEY]};
                          Transaction proxy_txn;
                          auto result{proxy_txn.parse_fields(proxy_field_list_node)};
                          if (result.is_ok()) {
                            key = proxy_txn.make_key(Key_Format);
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
                            erratum.error("Failed to parse server response at {}",
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
            erratum.error(R"("{}" value at {} is not a sequence.)", YAML_SSN_KEY,
                          ssn_list_node.Mark());
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

bool Parse_Request(swoc::TextView data, Transaction &txn) {
  if (swoc::TextView::npos == data.rfind("\r\n\r\n")) {
    return false;
  }
  auto first_line{data.take_prefix_at('\n')};
  if (first_line) {
    if (first_line.suffix(1)[0] == '\r') {
      first_line.remove_suffix(1);
    }
    auto method = first_line.take_prefix_at(' ');
  }
  while (data) {
    auto field{data.take_prefix_at('\n')};
    if (field.empty()) {
      continue;
    }
    auto name{field.take_prefix_at(':')};
    auto value = field.trim_if(&isspace);
  }
  return true;
}

void TF_Server(int socket_fd) {
  char buffer[MAX_REQ_HDR_SIZE];
  while (true) {
    sockaddr_in remote_addr;
    socklen_t remote_addr_size;
    int fd = accept(socket_fd, reinterpret_cast<sockaddr *>(&remote_addr), &remote_addr_size);
    auto n = read(fd, buffer, sizeof(buffer));
    Transaction proxy_req;
    if (Parse_Request({buffer, static_cast<size_t>(n)}, proxy_req)) {
      auto key{proxy_req.make_key(Key_Format)};
      auto spot{Transactions.find(key)};
      if (spot != Transactions.end()) {
        spot->second.transmit(fd);
        close(fd);
      }
    }
  }
}

void Engine::command_run() {
  swoc::IpEndpoint server_addr;
  TextView server_addr_arg { arguments.get("listen")[0] };

  if (! server_addr.parse(arguments.get("listen")[0])) {
    erratum.error(R"("{}" is not a valid IP address.)", server_addr_arg);
    return;
  }

  dirent **elements = nullptr;
  auto base_path { arguments.get("run")[1] };
  int n_sessions = scandir(base_path.c_str(), &elements, [](const dirent *entry) -> int {
    return 0 ==
           strcasecmp(swoc::TextView{entry->d_name, strlen(entry->d_name)}.suffix_at('.'), "json")
           ? 1 : 0;
  }, &alphasort);
  std::cout << "Loading " << n_sessions << " session files" << std::endl;

  std::array<std::thread, 10> threads;
  std::atomic_int idx{0};
  for (int x = 0; x < std::tuple_size<decltype(threads)>::value; ++x) {
    threads[x] = std::thread(TF_Load_Session, &idx, n_sessions, elements);
  }

  for (int x = 0; x < std::tuple_size<decltype(threads)>::value; ++x) {
    threads[x].join();
  }

  // After this, any string expected to be localized that isn't is an error, so lock down the
  // local string storage to avoid locking and report an error instead if not found.
  Local_String_Storage_Frozen = true;

  std::cout << "Finished" << std::endl;
  std::cout << Local_String_Storage.size() << " uniqueified strings" << std::endl;

  // Set up listen port.
  int socket_fd = socket(server_addr.family(), SOCK_STREAM, 0);
  bind(socket_fd, &server_addr.sa, server_addr.size());
  listen(socket_fd, 1);

  std::thread runner{TF_Server, socket_fd};
  runner.join();
};

int main(int argc, const char *argv[]) {
  Engine engine;

  engine.parser.add_option("--debug", "", "Enable debugging output")
      .add_option("--version", "-V", "Print version string")
      .add_option("--help", "-h", "Print usage information");

  engine.parser.add_command("run", "run <dir>: the replay server using data in <dir>", "", 1, [&]() -> void { engine.command_run(); })
      .add_option("--listen", "",  "Listen address and port", "", 1, "127.0.0.1:8080");

  // parse the arguments
  engine.arguments = engine.parser.parse(argv);

  engine.arguments.invoke();

  if (! engine.erratum.is_ok()) {
    std::cerr << engine.erratum;
  }
  return engine.status_code;
}

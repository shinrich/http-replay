#include <array>
#include <atomic>
#include <condition_variable>
#include <csignal>
#include <cstring>
#include <deque>
#include <mutex>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <libgen.h>

#include <bits/signum.h>
#include <dirent.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <unistd.h>
#include <fcntl.h>

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

struct ThreadInfo {
  std::thread *_thread = nullptr;
  std::condition_variable _cvar;
  std::mutex _mutex;
  Stream *_stream = nullptr;
};

// This must be a list so that iterators / pointers to elements do not go stale.
std::list<std::thread> All_Threads;
// Pool of ready / idle threads.
std::deque<ThreadInfo *> Thread_Pool;
std::condition_variable Thread_Pool_CVar;
std::mutex Thread_Pool_Mutex;

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

void TF_Serve(std::thread *t) {
  ThreadInfo info;
  info._thread = t;
  while (!Shutdown_Flag) {
    swoc::Errata errata;

    // ready to roll, add to the pool.
    {
      std::unique_lock<std::mutex> lock(Thread_Pool_Mutex);
      Thread_Pool.push_back(&info);
      Thread_Pool_CVar.notify_all();
    }

    // wait for a notification there's a stream to process.
    {
      std::unique_lock<std::mutex> lock(info._mutex);
      while (!info._stream) {
        info._cvar.wait(lock);
      }
    }

    while (!info._stream->is_closed() && errata.is_ok()) {
      HttpHeader req_hdr;
      swoc::LocalBufferWriter<MAX_HDR_SIZE> w;
      auto read_result{req_hdr.read_header(*(info._stream), w)};

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
              errata = req_hdr.drain_body(*(info._stream),
                                          w.view().substr(body_offset));
            }
            Info("Responding to request - status {}.", txn._rsp._status);
            errata = txn._rsp.transmit(*(info._stream));
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

    // cleanup and get ready for another stream.
    {
      std::unique_lock<std::mutex> lock(info._mutex);
      delete info._stream;
      info._stream = nullptr;
    }
  }
}

void TF_TLS_Accept(int socket_fd) {
  TLSStream reader;
  while (!Shutdown_Flag) {
    swoc::Errata errata;
    swoc::IPEndpoint remote_addr;
    socklen_t remote_addr_size;
    int fd =
        accept4(socket_fd, &remote_addr.sa, &remote_addr_size, 0);
    if (fd >= 0) {
      // The tls version of open will create the SSL object and bind the file descriptor
      // And make the blockig call to SSL_accept
      errata = reader.open(fd);
      if (errata.is_ok()) {
        static const int ONE = 1;
        setsockopt(socket_fd, IPPROTO_TCP, TCP_NODELAY, &ONE, sizeof(ONE));

        errata = reader.accept(); // Do the handshake
        if (errata.is_ok()) {
          TF_Serve(reader);
        } else {
          std::cerr << errata;
        }
      } else {
        std::cerr << errata;
      }
    }
  }
}

void TF_Accept(int socket_fd) {
  std::unique_ptr<Stream> stream;
  while (!Shutdown_Flag) {
    swoc::Errata errata;
    swoc::IPEndpoint remote_addr;
    socklen_t remote_addr_size;
    int fd =
        accept4(socket_fd, &remote_addr.sa, &remote_addr_size, 0);
    if (fd >= 0) {
      stream.reset(new Stream);
      errata = stream->open(fd);
      if (errata.is_ok()) {
        static const int ONE = 1;
        setsockopt(socket_fd, IPPROTO_TCP, TCP_NODELAY, &ONE, sizeof(ONE));
        ThreadInfo *tinfo = nullptr;
        {
          std::unique_lock<std::mutex> lock(Thread_Pool_Mutex);
          while (Thread_Pool.size() == 0) {
            // Some ugly stuff so that the thread can put a pointer to it's @c
            // std::thread in it's info. Circular dependency - there's no object
            // until after the constructor is called but the constructor needs
            // to be called to get the object. Sigh.
            All_Threads.emplace_back();
            // really? I have to do this to get an iterator / pointer to the
            // element I just added?
            std::thread *t = &*(std::prev(All_Threads.end()));
            *t = std::thread(
                TF_Serve,
                t); // move the temporary into the list element for permanence.
            Thread_Pool_CVar.wait(lock); // expect the new thread to enter
                                         // itself in the pool and signal.
          }
          tinfo = Thread_Pool.front();
          Thread_Pool.pop_front();
        }
        // Only pointer to worker thread info.
        {
          std::unique_lock<std::mutex> lock(tinfo->_mutex);
          tinfo->_stream = stream.release();
          tinfo->_cvar.notify_one();
        }
      } else {
        std::cerr << errata;
      }
    }
  }
}

swoc::Errata
do_listen(swoc::IPEndpoint &server_addr, void (*accept_func)(int))
{
  swoc::Errata errata;
  int socket_fd = socket(server_addr.family(), SOCK_STREAM, 0);
  if (socket_fd >= 0) {
    // Be agressive in reusing the port
    int ONE = 1;
    if (setsockopt(socket_fd, SOL_SOCKET, SO_REUSEADDR, &ONE, sizeof(int)) < 0) {
      errata.error(R"(Could not set reuseaddr on socket {} - {}.)", socket_fd,
                       swoc::bwf::Errno{});
    } else {
      int bind_result = bind(socket_fd, &server_addr.sa, server_addr.size());
      if (bind_result == 0) {
        int listen_result = listen(socket_fd, 1);
        if (listen_result == 0) {
          Info(R"(Listening at {})", server_addr);
          std::thread runner{accept_func, socket_fd};
          runner.join();
        } else {
          errata.error(R"(Could not isten to {} - {}.)", server_addr,
                       swoc::bwf::Errno{});
        }
      } else {
        errata.error(R"(Could not bind to {} - {}.)", server_addr,
                     swoc::bwf::Errno{});
      }
    }
  } else {
    errata.error(R"(Could not create socket - {}.)", swoc::bwf::Errno{});
  }
  if (socket_fd >= 0) {
    close(socket_fd);
  }
  return errata;
}

void Engine::command_run() {
  auto args{arguments.get("run")};
  swoc::IPEndpoint server_addr, server_addr_https;
  auto server_addr_arg{arguments.get("listen")};
  auto server_addr_https_arg{arguments.get("listen-https")};
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

  if (server_addr_https_arg) {
    if (server_addr_https_arg.size() == 1) {
      if (!server_addr_https.parse(server_addr_https_arg[0])) {
        errata.error(R"("{}" is not a valid IP address.)", server_addr_https_arg);
        return;
      }
    } else {
      errata.error(
          R"(--listen-https option must have a single value, the listen address and port.)");
    }
  }

  if (!server_addr.is_valid() && !server_addr_https.is_valid()) {
    errata.error(
        R"(Must specify a http or https listen port via --listen or --listen-https)");
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
  if (server_addr.is_valid()) {
    errata = do_listen(server_addr, TF_Accept);
  }
  if (!errata.is_ok()) {
    return;
  }
  if (server_addr_https.is_valid()) {
    errata = do_listen(server_addr_https, TF_TLS_Accept);
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
                  "")
      .add_option("--listen-https", "", "Listen TLS address and port", "", 1,
                  "");
  char certfile[PATH_MAX];
  strncpy(certfile, argv[0], sizeof(certfile));
  dirname(certfile);
  strncat(certfile, "/../server.pem", sizeof(certfile));
  TLSStream::certificate_file = certfile;
  strncpy(certfile, argv[0], sizeof(certfile));
  dirname(certfile);
  strncat(certfile, "/../server.key", sizeof(certfile));
  TLSStream::privatekey_file = certfile;
  TLSStream::init();

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

/** @file

  Common data structures and definitions for HTTP replay tools.

  @section license License

  Licensed to the Apache Software Foundation (ASF) under one or more contributor
  license agreements. See the NOTICE file distributed with this work for
  additional information regarding copyright ownership.  The ASF licenses this
  file to you under the Apache License, Version 2.0 (the "License"); you may not
  use this file except in compliance with the License.  You may obtain a copy of
  the License at

      http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
  License for the specific language governing permissions and limitations under
  the License.
 */

#pragma once

#include <string>
#include <unordered_set>

#include <condition_variable>
#include <deque>
#include <openssl/ssl.h>
#include <thread>
#include <unistd.h>

#include "yaml-cpp/yaml.h"

#include "swoc/BufferWriter.h"
#include "swoc/Errata.h"
#include "swoc/MemArena.h"
#include "swoc/TextView.h"
#include "swoc/bwf_base.h"
#include "swoc/ext/HashFNV.h"
#include "swoc/swoc_file.h"
#include "swoc/swoc_ip.h"

// Definitions of keys in the CONFIG files.
// These need to be @c std::string or the node look up will construct a @c
// std::string.
static const std::string YAML_SSN_KEY{"sessions"};
static const std::string YAML_SSN_PROTOCOL_KEY{"protocol"};
static const std::string YAML_SSN_START_KEY{"connection-time"};
static const std::string YAML_TXN_KEY{"transactions"};
static const std::string YAML_CLIENT_REQ_KEY{"client-request"};
static const std::string YAML_PROXY_REQ_KEY{"proxy-request"};
static const std::string YAML_SERVER_RSP_KEY{"server-response"};
static const std::string YAML_PROXY_RSP_KEY{"proxy-response"};
static const std::string YAML_HDR_KEY{"headers"};
static const std::string YAML_FIELDS_KEY{"fields"};
static const std::string YAML_HTTP_VERSION_KEY{"version"};
static const std::string YAML_HTTP_STATUS_KEY{"status"};
static const std::string YAML_HTTP_REASON_KEY{"reason"};
static const std::string YAML_HTTP_METHOD_KEY{"method"};
static const std::string YAML_HTTP_URL_KEY{"url"};
static const std::string YAML_CONTENT_KEY{"content"};
static const std::string YAML_CONTENT_LENGTH_KEY{"size"};

static constexpr size_t MAX_HDR_SIZE = 131072;	// Max our ATS is configured for
static constexpr size_t MAX_DRAIN_BUFFER_SIZE = 1 << 20;
/// HTTP end of line.
static constexpr swoc::TextView HTTP_EOL{"\r\n"};
/// HTTP end of header.
static constexpr swoc::TextView HTTP_EOH{"\r\n\r\n"};

extern bool Verbose;

/** A stream reader.
 * This is essential a wrapper around a socket to support use of @c epoll on the
 * socket. The goal is to enable a read operation that waits for data but
 * returns as soon as any data is available.
 */
class Stream {
public:
  Stream();
  virtual ~Stream();

  int fd() const;
  virtual ssize_t read(swoc::MemSpan<char> span);
  virtual ssize_t write(swoc::TextView data);
  virtual swoc::Errata accept();
  virtual swoc::Errata connect();

  virtual swoc::Errata open(int fd);
  bool is_closed() const;
  virtual void close();

protected:
  int _fd = -1; ///< Socket.
};

inline int Stream::fd() const { return _fd; }
inline bool Stream::is_closed() const { return _fd < 0; }

class TLSStream : public Stream {
public:
  using super = Stream;
  virtual ssize_t read(swoc::MemSpan<char> span) override;
  virtual ssize_t write(swoc::TextView data) override;
  ~TLSStream() override {
    if (_ssl)
      SSL_free(_ssl);
  }

  void close() override;
  swoc::Errata accept() override;
  swoc::Errata connect() override;
  static swoc::Errata init();
  static swoc::file::path certificate_file;
  static swoc::file::path privatekey_file;

protected:
  SSL *_ssl = nullptr;
  static SSL_CTX *server_ctx;
  static SSL_CTX *client_ctx;
};

class ChunkCodex {
public:
  /// The callback when a chunk is decoded.
  /// @param chunk Data for the chunk in the provided view.
  /// @param offset The offset from the full chunk for @a chunk.
  /// @param size The size of the full chunk.
  /// Because the data provided might not contain the entire chunk, a chunk can
  /// come back piecemeal in the callbacks. The @a offset and @a size specify
  /// where in the actual chunk the particular piece in @a chunk is placed.
  using ChunkCallback =
      std::function<bool(swoc::TextView chunk, size_t offset, size_t size)>;
  enum Result { CONTINUE, DONE, ERROR };

  /** Parse @a data as chunked encoded.
   *
   * @param data Data to parse.
   * @param cb Callback to receive decoded chunks.
   * @return Parsing result.
   *
   * The parsing is designed to be restartable so that data can be passed
   * directly from the socket to this object, without doing any gathering.
   */
  Result parse(swoc::TextView data, ChunkCallback const &cb);

  /** Write @a data to @a fd using chunked encoding.
   *
   * @param fd Output file descriptor.
   * @param data [in,out] Data to write.
   * @param chunk_size Size of chunks.
   * @return A pair of
   *   - The number of bytes written from @a data (not including the chunk
   * encoding).
   *   - An error code, which will be 0 if all data was successfully written.
   */
  std::tuple<ssize_t, std::error_code>
  transmit(Stream &stream, swoc::TextView data, size_t chunk_size = 4096);

protected:
  size_t _size = 0; ///< Size of the current chunking being decoded.
  size_t _off =
      0; ///< Number of bytes in the current chunk already sent to the callback.
  /// Buffer to hold size text in case it falls across @c parse call boundaries.
  swoc::LocalBufferWriter<16> _size_text;

  /// Parsing state.
  enum class State {
    INIT, ///< Initial state, no parsing has occurred.
    SIZE, ///< Parsing the chunk size.
    CR,   ///< Expecting the size terminating CR
    LF,   ///< Expecting the size terminating LF.
    BODY, ///< Inside the chunk body.
    POST_BODY_CR,
    POST_BODY_LF,
    FINAL ///< Terminating (size zero) chunk parsed.
  } _state = State::INIT;
};

class HttpHeader {
  using self_type = HttpHeader;
  using TextView = swoc::TextView;

  //  using NameSet = std::unordered_set<TextView, std::hash<std::string_view>>;
  struct Hash {
    swoc::Hash64FNV1a::value_type operator()(TextView view) const {
      return swoc::Hash64FNV1a{}.hash_immediate(
          swoc::transform_view_of(&tolower, view));
    }
    bool operator()(TextView lhs, TextView rhs) const {
      return 0 == strcasecmp(lhs, rhs);
    }
  };
  using NameSet = std::unordered_set<TextView, Hash, Hash>;
  using Fields = std::unordered_map<swoc::TextView, std::string, Hash, Hash>;

public:
  /// Parsing results.
  enum ParseResult {
    PARSE_OK,        ///< Parse finished sucessfully.
    PARSE_ERROR,     ///< Invalid data.
    PARSE_INCOMPLETE ///< Parsing not complete.
  };

  /// Important header fields.
  /// @{
  static TextView FIELD_CONTENT_LENGTH;
  static TextView FIELD_TRANSFER_ENCODING;
  /// @}

  /// Mark which status codes have no content by default.
  static std::bitset<600> STATUS_NO_CONTENT;

  HttpHeader() = default;
  HttpHeader(self_type const &) = delete;
  HttpHeader(self_type &&that) = default;
  self_type &operator=(self_type &&that) = default;

  /** Read and parse a header.
   *
   * @param reader [in,out] Data source.
   * @param w [in,out] Read buffer.
   * @return The size of the parsed header, or errors.
   *
   * Because the reading can overrun the header, the overrun must be made
   * available to the caller.
   * @a w is updated to mark all data read (via @c w.size() ). The return value
   * is the size of the header - data past that is the overrun.
   *
   * @note The reader may end up with a closed socket if the socket closes while
   * reading. This must be checked by the caller by calling @c
   * reader.is_closed().
   */
  swoc::Rv<ssize_t> read_header(Stream &reader, swoc::FixedBufferWriter &w);

  /** Write the header to @a fd.
   *
   * @param fd Ouput stream.
   */
  swoc::Errata transmit(Stream &stream) const;

  /** Write the body to @a fd.
   *
   * @param fd Outpuf file.
   * @return Errors, if any.
   *
   * This synthesizes the content based on values in the header.
   */
  swoc::Errata transmit_body(Stream &stream) const;

  /** Drain the content.
   *
   * @param fd [in,out]File to read. This is changed to -1 if closed while
   * draining.
   * @param initial Initial part of the body.
   * @return Errors, if any.
   *
   * If the return is an error, @a fd should be closed. It can be the case @a fd
   * is closed without an error, @a fd must be checked after the call to detect
   * this.
   *
   * @a initial is needed for cases where part of the content is captured while
   * trying to read the header.
   */
  swoc::Errata drain_body(Stream &stream, TextView initial) const;

  swoc::Errata load(YAML::Node const &node);
  swoc::Errata parse_fields(YAML::Node const &field_list_node);

  swoc::Rv<ParseResult> parse_request(TextView data);
  swoc::Rv<ParseResult> parse_response(TextView data);

  swoc::Errata update_content_length(TextView method);
  swoc::Errata update_transfer_encoding();

  std::string make_key();

  unsigned _status = 0;
  TextView _reason;
  unsigned _content_size = 0;
  TextView _method;
  TextView _http_version;
  std::string _url;
  Fields _fields;

  /// Body is chunked.
  unsigned _chunked_p : 1;
  /// No Content-Length - close after sending body.
  unsigned _content_length_p : 1;

  /// Format string to generate a key from a transaction.
  static TextView _key_format;

  /// String localization frozen?
  static bool _frozen;

  static void set_max_content_length(size_t n);

  static void global_init();

protected:
  class Binding : public swoc::bwf::NameBinding {
    using BufferWriter = swoc::BufferWriter;

  public:
    Binding(HttpHeader const &hdr) : _hdr(hdr) {}
    /** Override of virtual method to provide an implementation.
     *
     * @param w Output.
     * @param spec Format specifier for output.
     * @return @a w
     *
     * This is called from the formatting logic to generate output for a named
     * specifier. Subclasses that need to handle name dispatch differently need
     * only override this method.
     */
    BufferWriter &operator()(BufferWriter &w,
                             const swoc::bwf::Spec &spec) const override;

  protected:
    HttpHeader const &_hdr;
  };

  /** Convert @a name to a localized view.
   *
   * @param name Text to localize.
   * @return The localized view, or @a name if localization is frozen and @a
   * name is not found.
   *
   * @a name will be localized if string localization is not frozen, or @a name
   * is already localized.
   */
  static TextView localize(TextView text);

  static NameSet _names;
  static swoc::MemArena _arena;
  /// Precomputed content buffer.
  static swoc::MemSpan<char> _content;
};

// YAML support utilities.
namespace swoc {
inline BufferWriter &bwformat(BufferWriter &w, bwf::Spec const &spec,
                              YAML::Mark const &mark) {
  return w.print("line {}", mark.line);
}
} // namespace swoc

class ReplayFileHandler {
public:
  virtual swoc::Errata file_open(swoc::file::path const &path) { return {}; }
  virtual swoc::Errata file_close() { return {}; }
  virtual swoc::Errata ssn_open(YAML::Node const &node) { return {}; }
  virtual swoc::Errata ssn_close() { return {}; }
  virtual swoc::Errata txn_open(YAML::Node const &node) { return {}; }
  virtual swoc::Errata txn_close() { return {}; }
  virtual swoc::Errata client_request(YAML::Node const &node) { return {}; }
  virtual swoc::Errata proxy_request(YAML::Node const &node) { return {}; }
  virtual swoc::Errata server_response(YAML::Node const &node) { return {}; }
  virtual swoc::Errata proxy_response(YAML::Node const &node) { return {}; }
};

swoc::Errata Load_Replay_File(swoc::file::path const &path,
                              ReplayFileHandler &handler);

swoc::Errata
Load_Replay_Directory(swoc::file::path const &path,
                      swoc::Errata (*loader)(swoc::file::path const &),
                      int n_threads = 10);

swoc::Errata parse_ips(std::string arg, std::deque<swoc::IPEndpoint> &target);
swoc::Errata resolve_ips(std::string arg, std::deque<swoc::IPEndpoint> &target);
swoc::Rv<swoc::IPEndpoint> Resolve_FQDN(swoc::TextView host);

namespace swoc {
inline BufferWriter &bwformat(BufferWriter &w, bwf::Spec const &spec,
                              swoc::file::path const &path) {
  return bwformat(w, spec, path.string());
}
} // namespace swoc

namespace std {
template <typename R>
class tuple_size<swoc::Rv<R>> : public std::integral_constant<size_t, 2> {};
template <typename R> class tuple_element<0, swoc::Rv<R>> {
public:
  using type = R;
};
template <typename R> class tuple_element<1, swoc::Rv<R>> {
public:
  using type = swoc::Errata;
};
} // namespace std

template <typename... Args> void Info(swoc::TextView fmt, Args &&... args) {
  if (Verbose) {
    swoc::LocalBufferWriter<1024> w;
    w.print_v(fmt, std::forward_as_tuple(args...));
    if (w.error()) {
      std::string s;
      swoc::bwprint_v(s, fmt, std::forward_as_tuple(args...));
      std::cout << s << std::endl;
      std::cout << s << std::endl;
    } else {
      std::cout << w << std::endl;
    }
  }
}

class ThreadInfo {
public:
  std::thread *_thread = nullptr;
  std::condition_variable _cvar;
  std::mutex _mutex;
  virtual bool data_ready() = 0;
};

// This must be a list so that iterators / pointers to elements do not go stale.
class ThreadPool {
public:
  void wait_for_work(ThreadInfo *info);
  ThreadInfo *get_worker();
  virtual std::thread make_thread(std::thread *) = 0;
  void join_threads();

protected:
  std::list<std::thread> _allThreads;
  // Pool of ready / idle threads.
  std::deque<ThreadInfo *> _threadPool;
  std::condition_variable _threadPoolCvar;
  std::mutex _threadPoolMutex;
  const int max_threads = 2000;
};

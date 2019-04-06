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

static constexpr size_t MAX_REQ_HDR_SIZE = 65536;
static constexpr size_t MAX_RSP_HDR_SIZE = 65536;
static constexpr size_t MAX_DRAIN_BUFFER_SIZE = 1 << 20;
/// HTTP end of line.
static constexpr swoc::TextView HTTP_EOL{"\r\n"};
/// HTTP end of header.
static constexpr swoc::TextView HTTP_EOH{"\r\n\r\n"};

class ChunkCodex {
public:
  /// The callback when a chunk is decoded.
  /// @param chunk Data for the chunk in the provided view.
  /// @param offset The offset from the full chunk for @a chunk.
  /// @param size The size of the full chunk.
  /// Because the data provided might not contain the entire chunk, a chunk can
  /// come back piecemeal in the callbacks. The @a offset and @a size specify
  /// where in the actual chunk the particular piece in @a chunk is placed.
  using ChunkCallback = std::function<bool(swoc::TextView chunk, size_t offset, size_t size)>;
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
  std::tuple<ssize_t, std::error_code> transmit(int fd, swoc::TextView data,
                                               size_t chunk_size = 4096);

protected:
  size_t _size = 0; ///< Size of the current chunking being decoded.
  size_t _off =
      0; ///< Number of bytes in the current chunk already sent to the callback.
  /// Buffer to hold size text in case it falls across @c parse call boundaries.
  swoc::LocalBufferWriter<8> _size_text;

  /// Parsing state.
  enum class State {
    INIT, ///< Initial state, no parsing has occurred.
    SIZE, ///< Parsing the chunk size.
    CR,   ///< Expecting the size terminating CR
    LF,   ///< Expecting the size terminating LF.
    BODY, ///< Inside the chunk body.
    FINAL ///< Terminating (size zero) chunk parsed.
  } _state = State::INIT;
};

class HttpHeader {
  using Fields = std::unordered_map<swoc::TextView, std::string,
                                    std::hash<std::string_view>>;
  using TextView = swoc::TextView;

public:
  enum ParseResult { PARSE_OK, PARSE_ERROR, PARSE_INCOMPLETE };

  static TextView FIELD_CONTENT_LENGTH;
  static TextView FIELD_TRANSFER_ENCODING;

  static std::bitset<600> STATUS_NO_CONTENT;

  /** Write the header to @a fd.
   *
   * @param fd Ouput stream.
   */
  swoc::Errata transmit(int &fd) const;

  swoc::Errata transmit_body(int &fd) const;

  /** Drain the content.
   *
   * @param fd [in,out]File to read. This is changed to -1 if closed while draining.
   * @param initial Initial part of the body.
   * @return Errors, if any.
   *
   * If the return is an error, @a fd should be closed. It can be the case @a fd is closed
   * without an error, @a fd must be checked after the call to detect this.
   *
   * @a initial is needed for cases where part of the content is captured while trying to read
   * the header.
   */
  swoc::Errata drain_body(int &fd, TextView initial) const;

  swoc::Errata load(YAML::Node const &node);
  swoc::Errata parse_fields(YAML::Node const &field_list_node);

  swoc::Rv<ParseResult> parse_request(TextView data);
  swoc::Rv<ParseResult> parse_response(TextView data);

  swoc::Errata update_content_length();
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
  class Binding : public swoc::bwf::ContextNames<const HttpHeader> {
    using BufferWriter = swoc::BufferWriter;

  public:
  protected:
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

  static Binding _binding;
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

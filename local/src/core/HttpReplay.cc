/** @file

  Common implementation for HTTP replay.

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

#include "core/HttpReplay.h"

#include <dirent.h>
#include <netdb.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <unistd.h>

#include <thread>

#include "swoc/bwf_ex.h"
#include "swoc/bwf_std.h"

bool Verbose = false;

bool HttpHeader::_frozen = false;
swoc::MemArena HttpHeader::_arena{8000};
HttpHeader::NameSet HttpHeader::_names;
swoc::TextView HttpHeader::_key_format{"{field.uuid}"};
swoc::MemSpan<char> HttpHeader::_content;
swoc::TextView HttpHeader::FIELD_CONTENT_LENGTH;
swoc::TextView HttpHeader::FIELD_TRANSFER_ENCODING;
std::bitset<600> HttpHeader::STATUS_NO_CONTENT;

namespace {
[[maybe_unused]] bool INITIALIZED = []() -> bool {
  HttpHeader::global_init();
  return true;
}();
}

Stream::Stream() {}

Stream::~Stream() { this->close(); }

ssize_t Stream::read(swoc::MemSpan<char> span) {
  ssize_t n = ::read(_fd, span.data(), span.size());
  if (n <= 0) {
    this->close();
  }
  return n;
}

ssize_t TLSStream::read(swoc::MemSpan<char> span) {
  ssize_t n = -1;
  int ssl_error = 0;

  n = SSL_read(this->_ssl, span.data(), span.size());
  ssl_error = (n <= 0) ? SSL_get_error(_ssl, n) : 0;

  if ((n < 0 && ssl_error != SSL_ERROR_WANT_READ)) {
    fprintf(stderr, "read failed: n=%d ssl_err=%d %s\n", n,
            SSL_get_error(_ssl, n),
            ERR_lib_error_string(ERR_peek_last_error()));
    this->close();
  } else if (n == 0) {
    this->close();
  }
  return n;
}

ssize_t Stream::write(swoc::TextView view) {
  return ::write(_fd, view.data(), view.size());
}

ssize_t TLSStream::write(swoc::TextView view) {
  int total_size = view.size();
  int num_written = 0;
  while (num_written < total_size) {
    int n = SSL_write(this->_ssl, view.data() + num_written,
                      view.size() - num_written);
    if (n <= 0) {
      fprintf(stderr, "write failed: %s\n",
              ERR_lib_error_string(ERR_peek_last_error()));
      return n;
    } else {
      num_written += n;
    }
  }
  return num_written;
}

swoc::Errata Stream::open(int fd) {
  swoc::Errata errata;
  this->close();
  _fd = fd;
  return errata;
}

swoc::Errata Stream::accept() {
  swoc::Errata errata;
  return errata;
}
// Complate the TLS handshake
swoc::Errata TLSStream::accept() {
  swoc::Errata errata;
  _ssl = SSL_new(server_ctx);
  if (_ssl == nullptr) {
    errata.error(
        R"(Failed to create SSL server object fd={} server_ctx={} err={}.)",
        _fd, server_ctx, ERR_lib_error_string(ERR_peek_last_error()));
  } else {
    SSL_set_fd(_ssl, _fd);
    int retval = SSL_accept(_ssl);
    if (retval <= 0) {
      errata.error(
          R"(Failed SSL_accept {} {} {}.)", SSL_get_error(_ssl, retval),
          ERR_lib_error_string(ERR_peek_last_error()), swoc::bwf::Errno{});
    }
  }
  return errata;
}

swoc::Errata Stream::connect() {
  swoc::Errata errata;
  return errata;
}

// Complate the TLS handshake
swoc::Errata TLSStream::connect() {
  swoc::Errata errata;
  _ssl = SSL_new(client_ctx);
  if (_ssl == nullptr) {
    errata.error(
        R"(Failed to create SSL client object fd={} client_ctx={} err={}.)",
        _fd, client_ctx, ERR_lib_error_string(ERR_peek_last_error()));
  } else {
    SSL_set_fd(_ssl, _fd);
    int retval = SSL_connect(_ssl);
    if (retval <= 0) {
      errata.error(
          R"(Failed SSL_connect {} {} {}.)", SSL_get_error(_ssl, retval),
          ERR_lib_error_string(ERR_peek_last_error()), swoc::bwf::Errno{});
    }
  }
  return errata;
}

void Stream::close() {
  if (!this->is_closed()) {
    ::close(_fd);
    _fd = -1;
  }
}

void TLSStream::close() {
  if (!this->is_closed()) {
    if (_ssl != nullptr) {
      SSL_free(_ssl);
      _ssl = nullptr;
    }
    super::close();
  }
}

swoc::file::path TLSStream::certificate_file;
swoc::file::path TLSStream::privatekey_file;
SSL_CTX *TLSStream::server_ctx = nullptr;
SSL_CTX *TLSStream::client_ctx = nullptr;

swoc::Errata TLSStream::init() {
  swoc::Errata errata;
  SSL_load_error_strings();
  SSL_library_init();

  server_ctx = SSL_CTX_new(TLS_server_method());
  if (!TLSStream::certificate_file.empty()) {
    if (!SSL_CTX_use_certificate_file(server_ctx,
                                      TLSStream::certificate_file.c_str(),
                                      SSL_FILETYPE_PEM)) {
      errata.error(R"(Failed to load cert from "{}" - {}.)",
                   TLSStream::certificate_file,
                   ERR_lib_error_string(ERR_peek_last_error()));
    } else {
      if (!TLSStream::privatekey_file.empty()) {
        if (!SSL_CTX_use_PrivateKey_file(server_ctx,
                                         TLSStream::privatekey_file.c_str(),
                                         SSL_FILETYPE_PEM)) {
          errata.error(R"(Failed to load private key from "{}" - {}.)",
                       TLSStream::privatekey_file,
                       ERR_lib_error_string(ERR_peek_last_error()));
        }
      } else {
        if (!SSL_CTX_use_PrivateKey_file(server_ctx,
                                         TLSStream::certificate_file.c_str(),
                                         SSL_FILETYPE_PEM)) {
          errata.error(R"(Failed to load private key from "{}" - {}.)",
                       TLSStream::certificate_file,
                       ERR_lib_error_string(ERR_peek_last_error()));
        }
      }
    }
  }
  client_ctx = SSL_CTX_new(TLS_client_method());
  if (!client_ctx) {
    errata.error(R"(Failed to create client_ctx - {}.)",
                 ERR_lib_error_string(ERR_peek_last_error()));
  }
  return errata;
}

ChunkCodex::Result ChunkCodex::parse(swoc::TextView data,
                                     ChunkCallback const &cb) {
  while (data) {
    switch (_state) {
    case State::INIT:
      _state = State::SIZE;
      break;
    case State::SIZE:
      while (data && isxdigit(*data)) {
        _size_text.write(*data++);
      }
      if (data) {
        _size = swoc::svtou(_size_text.view(), nullptr, 16);
        _size_text.clear();
        _state = State::CR;
        break;
      }
    case State::CR:
      if (*data == '\r') {
        _state = State::LF;
      }
      ++data;
      break;
    case State::LF:
      if (*data == '\n') {
        if (_size) {
          _state = State::BODY;
          ++data;
          _off = 0;
        } else {
          _state = State::FINAL;
          return DONE;
        }
      }
      break;
    case State::BODY: {
      size_t n = std::min(data.size(), _size - _off);
      cb({data.data(), n}, _off, _size);
      data.remove_prefix(n);
      if ((_off += n) >= _size) {
        _state = State::SIZE;
      }
    } break;
    case State::FINAL:
      return DONE;
    }
  }
  return CONTINUE;
}

std::tuple<ssize_t, std::error_code>
ChunkCodex::transmit(Stream &stream, swoc::TextView data, size_t chunk_size) {
  static const std::error_code NO_ERROR;
  static constexpr swoc::TextView ZERO_CHUNK{"0\r\n"};

  swoc::LocalBufferWriter<10> w; // 8 bytes of size (32 bits) CR LF
  ssize_t n;
  ssize_t total = 0;
  w.print("{:x}{}", chunk_size, HTTP_EOL);
  while (data) {
    if (data.size() < chunk_size) {
      w.clear().print("{:x}{}", data.size(), HTTP_EOL);
      chunk_size = data.size();
    }
    n = stream.write(w.view());
    if (n > 0) {
      n = stream.write({data.data(), chunk_size});
      if (n > 0) {
        total += n;
        if (n == chunk_size) {
          data.remove_prefix(chunk_size);
        } else {
          return {total, std::error_code(errno, std::system_category())};
        }
      }
    } else {
      return {total, std::error_code(errno, std::system_category())};
    }
  }
  n = stream.write(ZERO_CHUNK);
  if (n != ZERO_CHUNK.size()) {
    return {total, std::error_code(errno, std::system_category())};
  }
  return {total, NO_ERROR};
};

void HttpHeader::global_init() {
  FIELD_CONTENT_LENGTH = localize("Content-Length");
  FIELD_TRANSFER_ENCODING = localize("Transfer-Encoding");

  STATUS_NO_CONTENT[204] = true;
  STATUS_NO_CONTENT[304] = true;
  for (auto code = 400; code < 600; code++) {
    STATUS_NO_CONTENT[code] = true;
  }
}

void HttpHeader::set_max_content_length(size_t n) {
  n = swoc::round_up<16>(n);
  _content.assign(static_cast<char *>(malloc(n)), n);
  for (size_t k = 0; k < n; k += 8) {
    swoc::FixedBufferWriter w{_content.data() + k, 8};
    w.print("{:07x} ", k / 8);
  };
}

swoc::Errata HttpHeader::update_content_length() {
  swoc::Errata errata;
  size_t cl = std::numeric_limits<size_t>::max();
  _content_length_p = false;
  if (auto spot{_fields.find(FIELD_CONTENT_LENGTH)}; spot != _fields.end()) {
    cl = swoc::svtou(spot->second);
    if (_content_size != 0 && cl != _content_size) {
      errata.info(R"(Conflicting sizes using "{}" value {} instead of {}.)", cl,
                  _content_size);
    }
    _content_size = cl;
    _content_length_p = true;
  }
  return errata;
}

swoc::Errata HttpHeader::update_transfer_encoding() {
  _chunked_p = false;
  if (auto spot{_fields.find(FIELD_TRANSFER_ENCODING)}; spot != _fields.end()) {
    if (0 == strcasecmp("chunked", spot->second)) {
      _chunked_p = true;
    }
  }
  return {};
}

swoc::Errata HttpHeader::transmit_body(Stream &stream) const {
  swoc::Errata errata;
  ssize_t n;
  std::error_code ec;

  Info("Transmit {} byte body {}{}.", _content_size,
       swoc::bwf::If(_content_length_p, "[CL]"),
       swoc::bwf::If(_chunked_p, "[chunked]"));
  if (_content_size || (_status && !STATUS_NO_CONTENT[_status])) {
    if (_chunked_p) {
      ChunkCodex codex;
      std::tie(n, ec) =
          codex.transmit(stream, {_content.data(), _content_size});
    } else {
      n = stream.write({_content.data(), _content_size});
      ec = std::error_code(errno, std::system_category());
      if (!_content_length_p) { // no content-length, must close to signal end
                                // of body.
        Info("No CL, status {} - closing.", _status);
        stream.close();
      }
    }
    if (n != _content_size) {
      errata.error(R"(Body write{} failed - {} of {} bytes written - {}.)",
                   swoc::bwf::If(_chunked_p, " [chunked]"), n, _content_size,
                   ec);
    }
  }

  return errata;
}

swoc::Errata HttpHeader::transmit(Stream &stream) const {
  swoc::Errata errata;

  if (_status) {
    swoc::LocalBufferWriter<MAX_HDR_SIZE> w;
    w.print("HTTP/{} {} {}{}", _http_version, _status, _reason, HTTP_EOL);
    for (auto const &[name, value] : _fields) {
      w.write(name).write(": ").write(value).write(HTTP_EOL);
    }
    w.write(HTTP_EOL);
    ssize_t n = stream.write(w.view());
    if (n == w.size()) {
      errata = this->transmit_body(stream);
    } else {
      errata.error(R"(Header write failed - {} of {} bytes written - {}.)", n,
                   w.size(), swoc::bwf::Errno{});
    }
  } else if (_method) {
    swoc::LocalBufferWriter<MAX_HDR_SIZE> w;
    w.print("{} {} HTTP/{}{}", _method, _url, _http_version, HTTP_EOL);
    for (auto const &[name, value] : _fields) {
      w.write(name).write(": ").write(value).write(HTTP_EOL);
    }
    w.write(HTTP_EOL);
    ssize_t n = stream.write({w.data(), w.size()});
    if (n == w.size()) {
      errata = this->transmit_body(stream);
    } else {
      errata.error(R"(Header write failed - {} of {} bytes written - {}.)", n,
                   w.size(), swoc::bwf::Errno{});
    }
  } else {
    errata.error(R"(Unable to write header - no status nor method.)");
  }
  return errata;
}

swoc::Errata HttpHeader::drain_body(Stream &stream,
                                    swoc::TextView initial) const {
  static constexpr size_t UNBOUNDED = std::numeric_limits<size_t>::max();
  swoc::Errata errata;
  size_t body_size = 0; // bytes drained for the content body.
  std::string buff;
  size_t content_length = _content_length_p ? _content_size : UNBOUNDED;
  if (content_length < initial.size()) {
    errata.error(
        R"(Response overrun - received {} bytes of content, expected {}.)",
        initial.size(), content_length);
    return errata;
  }

  // If there's a status, and it indicates no body, we're done.
  if (_status && STATUS_NO_CONTENT[_status] && !_content_length_p) {
    return errata;
  }

  buff.reserve(std::min<size_t>(content_length, MAX_DRAIN_BUFFER_SIZE));

  if (stream.is_closed()) {
    errata.error(R"(drain_body: stream closed)");
    return errata; 
  }

  if (_chunked_p) {
    ChunkCodex::ChunkCallback cb{
        [&](TextView block, size_t offset, size_t size) -> bool {
          body_size += block.size();
          return true;
        }};
    ChunkCodex codex;

    auto result = codex.parse(initial, cb);
    while (result == ChunkCodex::CONTINUE && body_size < content_length) {
      auto n{
          stream.read({buff.data(), std::min<size_t>(content_length - body_size,
                                                     MAX_DRAIN_BUFFER_SIZE)})};
      if (!stream.is_closed()) {
        result = codex.parse(TextView(buff.data(), n), cb);
      } else {
        if (content_length == UNBOUNDED) {
          // Is this an error? It's chunked, so an actual close seems unexpected
          // - should have parsed the empty chunk.
          Info("Connection closed on unbounded body.");
        } else {
          errata.error(
              R"(Response underrun - received {} bytes of content, expected {}, when file closed because {}.)",
              body_size, content_length, swoc::bwf::Errno{});
        }
        break;
      }
    }
    if (result != ChunkCodex::DONE ||
        (content_length != UNBOUNDED && body_size != content_length)) {
      errata.error(R"(Invalid response - expected {} bytes, drained {} byts.)",
                   content_length, body_size);
    }
    Info("Drained {} chunked bytes.", body_size);
  } else {
    body_size = initial.size();
    while (body_size < content_length) {
      ssize_t n = stream.read({buff.data(), std::min(content_length - body_size,
                                                     MAX_DRAIN_BUFFER_SIZE)});
      if (stream.is_closed()) {
        if (content_length == UNBOUNDED) {
          Info("Connection close on unbounded body");
        } else {
          errata.error(
              R"(Response underrun - received {} bytes  of content, expected {}, when file closed because {}.)",
              body_size, content_length, swoc::bwf::Errno{});
        }
        break;
      }
      body_size += n;
    }
    Info("Drained {} bytes.", body_size);
  }
  return errata;
}

swoc::Errata HttpHeader::parse_fields(YAML::Node const &field_list_node) {
  swoc::Errata errata;

  for (auto const &field_node : field_list_node) {
    if (field_node.IsSequence()) {
      if (2 <= field_node.size() && field_node.size() <= 3) {
        TextView name{this->localize(field_node[0].Scalar())};
        TextView value{field_node[1].Scalar()};
        _fields[name] = value;
      } else {
        errata.error(
            "Field at {} is not a sequence of length 2 or 3 as required.",
            field_node.Mark());
      }
    } else {
      errata.error("Field at {} is not a sequence as required.",
                   field_node.Mark());
    }
  }
  return errata;
}

swoc::Rv<ssize_t> HttpHeader::read_header(Stream &reader,
                                          swoc::FixedBufferWriter &w) {
  swoc::Rv<ssize_t> zret{-1};

  Info("Reading header.");
  while (w.remaining() > 0) {
    auto n = reader.read(w.aux_span());
    if (!reader.is_closed()) {
      // Where to start searching for the EOH string.
      size_t start =
          std::max<size_t>(w.size(), HTTP_EOH.size()) - HTTP_EOH.size();
      w.commit(n);
      size_t offset = w.view().substr(start).find(HTTP_EOH);
      if (TextView::npos != offset) {
        zret = start + offset + HTTP_EOH.size();
        break;
      }
    } else {
      if (w.size()) {
        zret.errata().error(
            R"(Connection closed unexpectedly after {} bytes while waiting for header - {}.)",
            w.size(), swoc::bwf::Errno{});
      } else {
        zret = 0; // clean close between transactions.
      }
      break;
    }
  }
  if (zret.is_ok() && zret == -1) {
    zret.errata().error(R"(Header exceeded maximum size {}.)", w.capacity());
  }
  return std::move(zret);
}

swoc::Errata HttpHeader::load(YAML::Node const &node) {
  swoc::Errata errata;

  if (node[YAML_HTTP_VERSION_KEY]) {
    _http_version = this->localize(node[YAML_HTTP_VERSION_KEY].Scalar());
  } else {
    _http_version = "1.1";
  }

  if (node[YAML_HTTP_STATUS_KEY]) {
    auto status_node{node[YAML_HTTP_STATUS_KEY]};
    if (status_node.IsScalar()) {
      TextView text{status_node.Scalar()};
      TextView parsed;
      auto n = swoc::svtou(text, &parsed);
      if (parsed.size() == text.size() && 0 < n && n <= 599) {
        _status = n;
      } else {
        errata.error(
            R"("{}" value "{}" at {} must an integer in the range [1..599].)",
            YAML_HTTP_STATUS_KEY, text, status_node.Mark());
      }
    } else {
      errata.error(R"("{}" value at {} must an integer in the range [1..599].)",
                   YAML_HTTP_STATUS_KEY, status_node.Mark());
    }
  }

  if (node[YAML_HTTP_REASON_KEY]) {
    auto reason_node{node[YAML_HTTP_REASON_KEY]};
    if (reason_node.IsScalar()) {
      _reason = this->localize(reason_node.Scalar());
    } else {
      errata.error(R"("{}" value at {} must a string.)", YAML_HTTP_REASON_KEY,
                   reason_node.Mark());
    }
  }

  if (node[YAML_HTTP_METHOD_KEY]) {
    auto method_node{node[YAML_HTTP_METHOD_KEY]};
    if (method_node.IsScalar()) {
      _method = this->localize(method_node.Scalar());
    } else {
      errata.error(R"("{}" value at {} must a string.)", YAML_HTTP_REASON_KEY,
                   method_node.Mark());
    }
  }

  if (node[YAML_HTTP_URL_KEY]) {
    auto url_node{node[YAML_HTTP_URL_KEY]};
    if (url_node.IsScalar()) {
      _url = url_node.Scalar();
    } else {
      errata.error(R"("{}" value at {} must a string.)", YAML_HTTP_URL_KEY,
                   url_node.Mark());
    }
  }

  if (node[YAML_CONTENT_KEY]) {
    auto content_node{node[YAML_CONTENT_KEY]};
    if (content_node.IsMap()) {
      if (content_node[YAML_CONTENT_LENGTH_KEY]) {
        _content_size =
            swoc::svtou(content_node[YAML_CONTENT_LENGTH_KEY].Scalar());
      }
    } else {
      errata.error(R"("{}" node at {} is not a map.)", YAML_CONTENT_KEY,
                   content_node.Mark());
    }
  }

  if (node[YAML_HDR_KEY]) {
    auto hdr_node{node[YAML_HDR_KEY]};
    if (hdr_node[YAML_FIELDS_KEY]) {
      auto field_list_node{hdr_node[YAML_FIELDS_KEY]};
      auto result{this->parse_fields(field_list_node)};
      if (result.is_ok()) {
        errata.note(this->update_content_length());
        errata.note(this->update_transfer_encoding());
      } else {
        errata.error("Failed to parse response at {}", node.Mark());
        errata.note(result);
      }
    }
  }

  if (0 == _status && !_method) {
    errata.error(
        R"(HTTP header at {} has neither a status as a response nor a method as a request.)",
        node.Mark());
  }

  return errata;
}

std::string HttpHeader::make_key() {
  swoc::FixedBufferWriter w{nullptr};
  std::string key;
  Binding binding(*this);
  w.print_n(binding, _key_format);
  key.resize(w.extent());
  swoc::FixedBufferWriter{key.data(), key.size()}.print_n(binding, _key_format);
  return std::move(key);
};

swoc::TextView HttpHeader::localize(TextView text) {
  auto spot = _names.find(text);
  if (spot != _names.end()) {
    return *spot;
  } else if (!_frozen) {
    auto span{_arena.alloc(text.size()).rebind<char>()};
    std::transform(text.begin(), text.end(), span.begin(), &tolower);
    TextView local{span.data(), text.size()};
    _names.insert(local);
    return local;
  }
  return text;
}

swoc::Rv<HttpHeader::ParseResult>
HttpHeader::parse_request(swoc::TextView data) {
  swoc::Rv<ParseResult> zret;

  if (swoc::TextView::npos == data.rfind(HTTP_EOH)) {
    zret = PARSE_INCOMPLETE;
  } else {
    data.remove_suffix(HTTP_EOH.size());

    auto first_line{data.take_prefix_at('\n')};
    if (first_line) {
      if (first_line.suffix(1)[0] == '\r') {
        first_line.remove_suffix(1);
      }
      _method = this->localize(first_line.prefix_if(&isspace));

      while (data) {
        auto field{data.take_prefix_at('\n').rtrim_if(&isspace)};
        if (field.empty()) {
          continue;
        }
        auto value{field};
        auto name{this->localize(value.take_prefix_at(':'))};
        value.trim_if(&isspace);
        if (name) {
          _fields[name] = value;
        } else {
          zret = PARSE_ERROR;
          zret.errata().error(R"(Malformed field "{}".)", field);
        }
      }
    } else {
      zret = PARSE_ERROR;
      zret.errata().error("Empty first line in request.");
    }
  }
  return zret;
}

swoc::Rv<HttpHeader::ParseResult>
HttpHeader::parse_response(swoc::TextView data) {
  swoc::Rv<ParseResult> zret;
  auto eoh = data.find(HTTP_EOH);

  if (swoc::TextView::npos == eoh) {
    zret = PARSE_INCOMPLETE;
  } else {
    data = data.prefix(eoh);

    auto first_line{data.take_prefix_at('\n').rtrim_if(&isspace)};
    if (first_line) {
      auto version{first_line.take_prefix_if(&isspace)};
      auto status{first_line.ltrim_if(&isspace).take_prefix_if(&isspace)};
      _status = swoc::svtou(status);

      while (data) {
        auto field{data.take_prefix_at('\n').rtrim_if(&isspace)};
        if (field.empty()) {
          continue;
        }
        auto value{field};
        //        auto name{this->localize(value.take_prefix_at(':'))};
        auto name{value.take_prefix_at(':')};
        value.trim_if(&isspace);
        if (name) {
          _fields[name] = value;
        } else {
          zret = PARSE_ERROR;
          zret.errata().error(R"(Malformed field "{}".)", field);
        }
      }
    } else {
      zret = PARSE_ERROR;
      zret.errata().error("Empty first line in response.");
    }
  }
  return zret;
}

swoc::BufferWriter &HttpHeader::Binding::
operator()(BufferWriter &w, const swoc::bwf::Spec &spec) const {
  static constexpr TextView FIELD_PREFIX{"field."};
  TextView name{spec._name};
  if (name.starts_with_nocase(FIELD_PREFIX)) {
    name.remove_prefix(FIELD_PREFIX.size());
    if (auto spot{_hdr._fields.find(name)}; spot != _hdr._fields.end()) {
      bwformat(w, spec, spot->second);
    } else {
      bwformat(w, spec, "*N/A*");
    }
  } else {
    bwformat(w, spec, "*N/A*");
  }
  return w;
}

swoc::Errata Load_Replay_File(swoc::file::path const &path,
                              ReplayFileHandler &handler) {
  swoc::Errata errata;
  std::error_code ec;
  errata = handler.file_open(path);
  if (errata.is_ok()) {
    std::string content{swoc::file::load(path, ec)};
    if (ec.value()) {
      errata.error(R"(Error loading "{}": {})", path, ec);
    } else {
      YAML::Node root;
      try {
        root = YAML::Load(content);
      } catch (std::exception const &ex) {
        errata.warn(R"(Exception: {} in "{}".)", ex.what(), path);
      }
      if (errata.is_ok()) {
        if (root[YAML_SSN_KEY]) {
          auto ssn_list_node{root[YAML_SSN_KEY]};
          if (ssn_list_node.IsSequence()) {
            if (ssn_list_node.size() > 0) {
              for (auto const &ssn_node : ssn_list_node) {
                auto result{handler.ssn_open(ssn_node)};
                if (result.is_ok()) {
                  if (ssn_node[YAML_TXN_KEY]) {
                    auto txn_list_node{ssn_node[YAML_TXN_KEY]};
                    if (txn_list_node.IsSequence()) {
                      if (txn_list_node.size() > 0) {
                        for (auto const &txn_node : txn_list_node) {
                          if (txn_node[YAML_PROXY_REQ_KEY] &&
                              txn_node[YAML_SERVER_RSP_KEY] &&
                              txn_node[YAML_CLIENT_REQ_KEY] &&
                              txn_node[YAML_PROXY_RSP_KEY]) {
                            result.note(handler.txn_open(txn_node));
                            if (result.is_ok()) {
                              result.note(handler.client_request(
                                  txn_node[YAML_CLIENT_REQ_KEY]));
                              result.note(handler.proxy_request(
                                  txn_node[YAML_PROXY_REQ_KEY]));
                              result.note(handler.server_response(
                                  txn_node[YAML_SERVER_RSP_KEY]));
                              result.note(handler.proxy_response(
                                  txn_node[YAML_PROXY_RSP_KEY]));
                              result.note(handler.txn_close());
                            }
                            errata = std::move(result);
                          } else {
                            errata.error(
                                R"(Transaction node at {} in "{}" did not contain all four required HTTP header keys.)",
                                txn_node.Mark(), path);
                          }
                        }
                      } else {
                        errata.info(
                            R"(Transaction list at {} in session at {} in "{}" is an empty list.)",
                            txn_list_node.Mark(), ssn_node.Mark(), path);
                      }
                    } else {
                      errata.error(
                          R"(Transaction list at {} in session at {} in "{}" is not a list.)",
                          txn_list_node.Mark(), ssn_node.Mark(), path);
                    }
                  } else {
                    errata.error(R"(Session at {} in "{}" has no "{}" key.)",
                                 ssn_node.Mark(), path, YAML_TXN_KEY);
                  }
                  result.note(handler.ssn_close());
                } else {
                  errata.note(result);
                }
              }
            } else {
              errata.info(R"(Session list at {} in "{}" is an empty list.)",
                          ssn_list_node.Mark(), path);
            }
          } else {
            errata.error(R"("{}" value at {} in "{}" is not a sequence.)",
                         YAML_SSN_KEY, ssn_list_node.Mark(), path);
          }
        } else {
          errata.error(R"(Failed to parse "{}".)", path.c_str());
        }
      }
    }
    handler.file_close();
  }
  return errata;
}

swoc::Errata
Load_Replay_Directory(swoc::file::path const &path,
                      swoc::Errata (*loader)(swoc::file::path const &),
                      int n_threads) {
  swoc::Errata errata;
  std::mutex local_mutex;

  dirent **elements = nullptr;

  if (0 == chdir(path.c_str())) {
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
    if (n_sessions > 0) {
      std::atomic<int> idx{0};
      swoc::MemSpan<dirent *> entries{elements,
                                      static_cast<size_t>(n_sessions)};

      // Lambda suitable to spawn in a thread to load files.
      auto load_wrapper = [&]() -> void {
        int k;
        while ((k = idx++) < entries.count()) {
          auto result = (*loader)(swoc::file::path{entries[k]->d_name});
          std::lock_guard<std::mutex> lock(local_mutex);
          errata.note(result);
        }
      };

      Info("Loading {} replay files.", n_sessions);
      std::vector<std::thread> threads;
      threads.reserve(n_threads);
      for (int tidx = 0; tidx < n_threads; ++tidx) {
        threads.emplace_back(load_wrapper);
      }
      for (std::thread &thread : threads) {
        thread.join();
      }
    } else {
      errata.error(R"(No replay files found in "{}".)", path);
    }
  } else {
    errata.error(R"(Failed to access directory "{}" - {}.)", path,
                 swoc::bwf::Errno{});
  }
  return errata;
}

swoc::Errata parse_ips(std::string arg, std::deque<swoc::IPEndpoint> &target)
{
  swoc::Errata errata;
  int offset = 0;
  int new_offset;
  while (offset != std::string::npos) {
    new_offset = arg.find(',', offset);
    std::string name = arg.substr(offset, new_offset - offset);
    offset = new_offset != std::string::npos ? new_offset + 1 : new_offset;
    swoc::IPEndpoint addr;
    if (!addr.parse(name)) {
      errata.error(R"("{}" is not a valid IP address.)", name);
      return errata;
    }
    target.push_back(addr);
  } 
  return errata;
}

swoc::Errata resolve_ips(std::string arg, std::deque<swoc::IPEndpoint> &target)
{
  swoc::Errata errata;
  int offset = 0;
  int new_offset;
  while (offset != std::string::npos) {
    new_offset = arg.find(',', offset);
    std::string name = arg.substr(offset, new_offset - offset);
    offset = new_offset != std::string::npos ? new_offset + 1 : new_offset;
    auto &&[tmp_target, result] = Resolve_FQDN(name);
    if (!result.is_ok()) {
      errata.error(R"("{}" is not a valid IP address.)", name);
      return errata;
    }
    target.push_back(tmp_target);
  } 
  return errata;
}

swoc::Rv<swoc::IPEndpoint> Resolve_FQDN(swoc::TextView fqdn) {
  swoc::Rv<swoc::IPEndpoint> zret;
  swoc::TextView host_str, port_str;
  in_port_t port;
  static constexpr in_port_t MAX_PORT{std::numeric_limits<in_port_t>::max()};

  if (swoc::IPEndpoint::tokenize(fqdn, &host_str, &port_str)) {
    swoc::IPAddr addr;
    if (port_str) {
      swoc::TextView text(port_str);
      auto n = swoc::svto_radix<10>(text);
      if (text.empty() && 0 < n && n <= MAX_PORT) {
        port = htons(n);
        if (addr.parse(host_str)) {
          zret.result().assign(addr, port);
        } else {
          addrinfo *addrs;
          addrinfo hints;
          char buff[host_str.size() + 1];
          memcpy(buff, host_str.data(), host_str.size());
          buff[host_str.size()] = '\0';
          hints.ai_family = AF_UNSPEC;
          hints.ai_socktype = SOCK_STREAM;
          hints.ai_protocol = IPPROTO_TCP;
          hints.ai_flags = 0;
          auto result = getaddrinfo(buff, nullptr, &hints, &addrs);
          if (0 == result) {
            zret.result().assign(addrs->ai_addr);
            zret.result().port() = port;
            freeaddrinfo(addrs);
          } else {
            zret.errata().error(R"(Failed to resolve "{}" - {}.)", host_str,
                                swoc::bwf::Errno(result));
          }
        }
      } else {
        zret.errata().error(R"(Port value {} out of range [ 1 .. {} ].)",
                            port_str, MAX_PORT);
      }
    } else {
      zret.errata().error(
          R"(Address "{}" does not have the require port specifier.)", fqdn);
    }

  } else {
    zret.errata().error(R"(Malformed address "{}".)", fqdn);
  }
  return std::move(zret);
}

using namespace std::chrono_literals;

void ThreadPool::wait_for_work(ThreadInfo *info) {
  // ready to roll, add to the pool.
  {
    std::unique_lock<std::mutex> lock(_threadPoolMutex);
    _threadPool.push_back(info);
    _threadPoolCvar.notify_all();
  }

  // wait for a notification there's a stream to process.
  {
    std::unique_lock<std::mutex> lock(info->_mutex);
    bool condition_awoke = false;
    while (!info->data_ready() && !condition_awoke) {
      info->_cvar.wait_for(lock, 100ms);
    }
  }
}

ThreadInfo *ThreadPool::get_worker() {
  ThreadInfo *tinfo = nullptr;
  {
    std::unique_lock<std::mutex> lock(this->_threadPoolMutex);
    while (_threadPool.size() == 0) {
      if (_allThreads.size() > max_threads) {
        // Just sleep until a thread comes back
        _threadPoolCvar.wait(lock);
      } else { // Make a new thread
        // Some ugly stuff so that the thread can put a pointer to it's @c
        // std::thread in it's info. Circular dependency - there's no object
        // until after the constructor is called but the constructor needs
        // to be called to get the object. Sigh.
        _allThreads.emplace_back();
        // really? I have to do this to get an iterator / pointer to the
        // element I just added?
        std::thread *t = &*(std::prev(_allThreads.end()));
        *t = this->make_thread(t);
        _threadPoolCvar.wait(lock); // expect the new thread to enter
                                    // itself in the pool and signal.
      }
    }
    tinfo = _threadPool.front();
    _threadPool.pop_front();
  }
  return tinfo;
}

void ThreadPool::join_threads() {
  for (auto &thread : _allThreads) {
    thread.join();
  }
}

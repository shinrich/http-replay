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
#include <unistd.h>

#include <thread>

#include "swoc/bwf_ex.h"
#include "swoc/bwf_std.h"

bool HttpHeader::_frozen = false;
swoc::MemArena HttpHeader::_arena{8000};
HttpHeader::NameSet HttpHeader::_names;
HttpHeader::Binding HttpHeader::_binding;
swoc::TextView HttpHeader::_key_format{"{field.uuid}"};
swoc::MemSpan<char> HttpHeader::_content;

void HttpHeader::set_max_content_length(size_t n) {
  n = swoc::round_up<16>(n);
  _content.assign(static_cast<char *>(malloc(n)), n);
  for (size_t k = 0; k < n; k += 8) {
    swoc::FixedBufferWriter w{_content.data() + k, 8};
    w.print("{:07x} ", k / 8);
  };
}

swoc::Errata HttpHeader::transmit(int fd) const {
  swoc::Errata errata;

  if (_status) {
    swoc::LocalBufferWriter<MAX_RSP_HDR_SIZE> w;
    w.print("HTTP/{} {} {}{}", _http_version, _status, _reason, HTTP_EOL);
    for (auto const &[name, value] : _fields) {
      w.write(name).write(": ").write(value).write(HTTP_EOL);
    }
    w.write(HTTP_EOL);
    write(fd, w.data(), w.size());
    write(fd, _content.data(), _content_size);
  } else if (_method) {
    swoc::LocalBufferWriter<MAX_REQ_HDR_SIZE> w;
    w.print("{} {} HTTP/{}{}", _method, _url, _http_version);
    for (auto const &[name, value] : _fields) {
      w.write(name).write(": ").write(value).write(HTTP_EOL);
    }
    w.write(HTTP_EOL);
    write(fd, w.data(), w.size());
  } else {
    errata.error(R"(Transmit failed - no status nor method.)");
  }
  return errata;
}

swoc::Errata HttpHeader::parse_fields(YAML::Node const &field_list_node) {
  swoc::Errata errata;

  for (auto const &field_node : field_list_node) {
    if (field_node.IsSequence()) {
      if (field_node.size() == 2) {
        TextView name{this->localize(field_node[0].Scalar())};
        TextView value{field_node[1].Scalar()};
        _fields[name] = value;
      } else {
        errata.error("Field at {} is not a sequence of length 2 as required.",
                     field_node.Mark());
      }
    } else {
      errata.error("Field at {} is not a sequence as required.",
                   field_node.Mark());
    }
  }
  return errata;
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
      if (!result.is_ok()) {
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
  w.print_n(_binding.bind(*this), _key_format);
  key.resize(w.extent());
  swoc::FixedBufferWriter{key.data(), key.size()}.print_n(_binding.bind(*this),
                                                          _key_format);
  return std::move(key);
};

swoc::TextView HttpHeader::localize(TextView text) {
  auto spot = _names.find(text);
  if (spot != _names.end()) {
    return *spot;
  } else if (!_frozen) {
    auto span{_arena.alloc(text.size()).rebind<char>()};
    memcpy(span.data(), text.data(), text.size());
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

      while (data) {
        auto field{data.take_prefix_at('\n')};
        if (field.empty()) {
          continue;
        }
        auto value{field};
        auto name{this->localize(value.take_prefix_at(':'))};
        value.trim_if(&isspace);
        if (name && value) {
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

swoc::BufferWriter &HttpHeader::Binding::
operator()(BufferWriter &w, const swoc::bwf::Spec &spec) const {
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

swoc::Errata Load_Replay_File(swoc::file::path const &path,
                              ReplayFileHandler &handler) {
  swoc::Errata errata;
  std::error_code ec;
  std::string content{swoc::file::load(path, ec)};
  if (ec.value()) {
    errata.error(R"(Error loading "{}": {})", path, ec);
  } else {
    YAML::Node root;
    try {
      root = YAML::Load(content);
    } catch (std::exception const &ex) {
      errata.error(R"(Exception: {} in "{}".)", ex.what(), path);
    }
    if (errata.is_ok()) {
      if (root[YAML_SSN_KEY]) {
        auto ssn_list_node{root[YAML_SSN_KEY]};
        if (ssn_list_node.IsSequence()) {
          if (ssn_list_node.size() > 0) {
            for (auto const &ssn_node : ssn_list_node) {
              if (ssn_node[YAML_TXN_KEY]) {
                auto txn_list_node{ssn_node[YAML_TXN_KEY]};
                if (txn_list_node.IsSequence()) {
                  if (txn_list_node.size() > 0) {
                    auto result{handler.ssn_open(txn_list_node)};
                    if (result.is_ok()) {
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
                      result.note(handler.ssn_close());
                    }
                    errata.note(result);
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

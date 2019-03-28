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
#include <unistd.h>

bool HttpHeader::_frozen = false;
swoc::MemArena HttpHeader::_arena{8000};
HttpHeader::NameSet HttpHeader::_names;
HttpHeader::Binding HttpHeader::_binding;
swoc::TextView HttpHeader::_key_format{"{field.uuid}"};

void HttpHeader::transmit(int fd) {
  swoc::LocalBufferWriter<MAX_RSP_HDR_SIZE> w;
  w.print("200 OK\r\n");
  for (auto const &[name, value] : _fields) {
    w.write(name).write(": ").write(value).write(HTTP_EOL);
  }
  w.write(HTTP_EOL);
  write(fd, w.data(), w.size());
}

swoc::Errata HttpHeader::parse_fields(YAML::Node const &field_list_node) {
  swoc::Errata erratum;

  for (auto const &field_node : field_list_node) {
    if (field_node.IsSequence()) {
      if (field_node.size() == 2) {
        auto name{this->localize(field_node[0].Scalar())};
        TextView value{field_node[1].Scalar()};
        if (name.is_ok()) {
          _fields[name] = value;
        } else {
          erratum.error("Unexpected field name.");
          erratum.note(name.errata());
          break;
        }
      } else {
        erratum.error("Field at {} is not a sequence of length 2 as required.",
                      field_node.Mark());
      }
    } else {
      erratum.error("Field at {} is not a sequence as required.",
                    field_node.Mark());
    }
  }
  return erratum;
}

std::string HttpHeader::make_key(TextView fmt) {
  swoc::FixedBufferWriter w{nullptr};
  std::string key;
  w.print_n(_binding.bind(*this), fmt);
  key.resize(w.extent());
  swoc::FixedBufferWriter{key.data(), key.size()}.print_n(_binding.bind(*this),
                                                          fmt);
  return std::move(key);
};

auto HttpHeader::localize(TextView name) -> swoc::Rv<TextView> {
  auto spot = _names.find(name);
  if (spot != _names.end()) {
    return *spot;
  } else if (!_frozen) {
    auto span{_arena.alloc(name.size()).rebind<char>()};
    memcpy(span.data(), name.data(), name.size());
    TextView local{span.data(), name.size()};
    _names.insert(local);
    return local;
  } else {
    swoc::Errata erratum;
    erratum.error(R"(Non-localized string "{}")", name);
    return {{}, std::move(erratum)};
  }
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
        auto name_result{this->localize(field.take_prefix_at(':'))};
        if (name_result.is_ok()) {
          _fields[name_result] = field.ltrim_if(&isspace);
        } else {
          zret.errata().error(R"(Unexpected field name "{}" in request.)",
                              name_result.result());
          break;
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
  swoc::Errata erratum;
  std::error_code ec;
  std::string content{swoc::file::load(path, ec)};
  if (ec.value()) {
    erratum.error(R"(Error loading "{}": {})", path, ec);
  } else {
    YAML::Node root;
    try {
      root = YAML::Load(content);
    } catch (std::exception const &ex) {
      erratum.error("Exception: {}", ex.what());
    }
    if (erratum.is_ok()) {
      if (root[YAML_SSN_KEY]) {
        auto ssn_list_node{root[YAML_SSN_KEY]};
        if (ssn_list_node.IsSequence()) {
          if (ssn_list_node.size() > 0) {
            for (auto const &ssn_node : ssn_list_node) {
              if (ssn_node[YAML_TXN_KEY]) {
                auto txn_list_node{ssn_node[YAML_TXN_KEY]};
                if (txn_list_node.IsSequence()) {
                  if (txn_list_node.size() > 0) {
                    handler.ssn_open(txn_list_node);
                    for (auto const &txn_node : txn_list_node) {
                      if (txn_node[YAML_PROXY_REQ_KEY] &&
                          txn_node[YAML_SERVER_RSP_KEY] &&
                          txn_node[YAML_CLIENT_REQ_KEY] &&
                          txn_node[YAML_PROXY_RSP_KEY]) {
                        handler.txn_open(txn_node);
                        handler.client_request(txn_node[YAML_CLIENT_REQ_KEY]);
                        handler.proxy_request(txn_node[YAML_PROXY_REQ_KEY]);
                        handler.server_response(txn_node[YAML_SERVER_RSP_KEY]);
                        handler.proxy_response(txn_node[YAML_PROXY_RSP_KEY]);
                        handler.txn_close();
                      } else {
                        erratum.error("Transaction node at {} did not contain "
                                      "all four required HTTP header keys.",
                                      txn_node.Mark());
                      }
                    }
                  } else {
                    erratum.warn(
                        R"(Transaction list at {} in session at {} is an empty list.)",
                        txn_list_node.Mark(), ssn_node.Mark());
                  }
                } else {
                  erratum.error(
                      R"(Transaction list at {} in session at {} is not a list.)",
                      txn_list_node.Mark(), ssn_node.Mark());
                }
              } else {
                erratum.error(R"(Session at {} has no "{}" key.)",
                              ssn_node.Mark(), YAML_TXN_KEY);
              }
            }
          } else {
            erratum.error(R"(Session list at {} is an empty list.)",
                          ssn_list_node.Mark());
          }
        } else {
          erratum.error(R"("{}" value at {} is not a sequence.)", YAML_SSN_KEY,
                        ssn_list_node.Mark());
        }
      } else {
        erratum.error(R"(Failed to parse "{}".)", path.c_str());
      }
    }
  }
  return erratum;
}

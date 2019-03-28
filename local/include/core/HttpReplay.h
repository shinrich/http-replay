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
#include "swoc/swoc_file.h"

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

static constexpr size_t MAX_REQ_HDR_SIZE = 65536;
static constexpr size_t MAX_RSP_HDR_SIZE = 65536;

/// HTTP end of line.
static constexpr swoc::TextView HTTP_EOL{"\r\n"};
/// HTTP end of header.
static constexpr swoc::TextView HTTP_EOH{"\r\n\r\n"};

class HttpHeader {
  using Fields = std::unordered_map<swoc::TextView, std::string,
                                    std::hash<std::string_view>>;
  using TextView = swoc::TextView;

public:
  enum ParseResult { PARSE_OK, PARSE_ERROR, PARSE_INCOMPLETE };

  /** Write the transaction to @a fd.
   *
   * @param fd Ouput stream.
   */
  void transmit(int fd);

  swoc::Errata parse_fields(YAML::Node const &field_list_node);

  swoc::Rv<ParseResult> parse_request(TextView data);

  std::string make_key(TextView fmt);

  unsigned _status = 0;
  unsigned _content_size = 0;
  Fields _fields;

  /// Format string to generate a key from a transaction.
  static TextView _key_format;

  /// String localization frozen?
  static bool _frozen;

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

  swoc::Rv<TextView> localize(TextView name);

  static Binding _binding;
  using NameSet = std::unordered_set<TextView, std::hash<std::string_view>>;
  static NameSet _names;
  static swoc::MemArena _arena;
};

// YAML support utilities.
namespace swoc {
BufferWriter &bwformat(BufferWriter &w, bwf::Spec const &spec,
                       YAML::Mark const &mark) {
  return w.print("line {}", mark.line);
}
} // namespace swoc

class ReplayFileHandler {
public:
  virtual swoc::Errata ssn_open(YAML::Node const &node) {}
  virtual swoc::Errata ssn_close() {}
  virtual swoc::Errata txn_open(YAML::Node const &node) {}
  virtual swoc::Errata txn_close() {}
  virtual swoc::Errata client_request(YAML::Node const &node) {}
  virtual swoc::Errata proxy_request(YAML::Node const &node) {}
  virtual swoc::Errata server_response(YAML::Node const &node) {}
  virtual swoc::Errata proxy_response(YAML::Node const &node) {}
};

swoc::Errata Load_Replay_File(swoc::file::path const &path, ReplayFileHandler &handler);

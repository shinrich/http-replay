#include <list>
#include <thread>

#include "core/ArgParser.h"
#include "core/HttpReplay.h"

struct Txn {
  HttpHeader _req; ///< Request to send.
  HttpHeader _rsp; ///< Response to expect.
};

using Session = std::list<Txn>;

std::list<Session> Session_List;

/** Command execution.
 *
 * This handles parsing and acting on the command line arguments.
 */
struct Engine {
  ts::ArgParser parser;    ///< Command line argument parser.
  ts::Arguments arguments; ///< Results from argument parsing.

  static constexpr swoc::TextView COMMAND_RUN{"run"};
  static constexpr swoc::TextView COMMAND_RUN_ARGS{
      "Arguments:\n\t<dir>: Directory containing replay files.\n\t<upstream>: "
      "Upstream destination for requests."};
  void command_run();

  /// Status code to return to the operating system.
  int status_code = 0;
  /// Error reporting.
  swoc::Errata erratum;
};

void Engine::command_run() {
  auto args{arguments.get("run")};
  bool proxy_p = false;

  if (args.size() < 2) {
    erratum.error(R"(Not enough arguments for "{}" command.\n{})", COMMAND_RUN,
                  COMMAND_RUN_ARGS);
    status_code = 1;
    return;
  }

  if (arguments.get("--no-proxy")) {
    proxy_p = true;
  }
};

int main(int argc, const char *argv[]) {
  Engine engine;

  engine.parser.add_option("--debug", "", "Enable debugging output")
      .add_option("--version", "-V", "Print version string")
      .add_option("--help", "-h", "Print usage information");

  engine.parser
      .add_command(Engine::COMMAND_RUN.data(), Engine::COMMAND_RUN_ARGS.data(),
                   "", MORE_THAN_ONE_ARG_N,
                   [&]() -> void { engine.command_run(); })
      .add_option("--no-proxy", "Use proxy data instead of client data.");

  // parse the arguments
  engine.arguments = engine.parser.parse(argv);

  engine.arguments.invoke();

  if (!engine.erratum.is_ok()) {
    std::cerr << engine.erratum;
  }
  return engine.status_code;
}

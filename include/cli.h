//
// Copyright (c) 2025 Nick Marino
// All rights reserved.
//

//
// cli.h
//
// This header file declares a command line interface to parse container
// management commands. 
//

#ifndef HTOOL_CLI_H_
#define HTOOL_CLI_H_

#include <string>
#include <vector>

namespace htool::cli {

/// Possible kinds of command line commands.
enum class Command {
    Make = 0,
    Remove,
    Store,
    Load,
    Delete,
    List,
};

/// Represents a set of parsed options from the command line.
struct CLIOptions {
    std::string container;
    std::string password;
    Command cmd;
    std::vector<std::string> paths;
    bool print_version;
    bool compact;
};

//! Returns a structure of parsed options from a set of command line 
//! arguments |argv| of size |argc|.
[[nodiscard]] CLIOptions parse(int argc, char** argv);

//! Prints the informative message |msg|.
void info(const std::string& msg);

//! Quits the program with the error message |msg|.
[[noreturn]] void fatal(const std::string& msg);

} // namespace htool::cli

#endif // HTOOL_CLI_H_

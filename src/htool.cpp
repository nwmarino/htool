//
// Copyright (c) 2025 Nick Marino
// All rights reserved.
//

//
// htool.cpp
//
// The following source defines the entry point and main driver for htool.
//

#include "cli.h"
#include "common.h"
#include "container.h"

#include "boost/filesystem/operations.hpp"

#include <string>

namespace fs = boost::filesystem;

using namespace htool;

int main(int argc, char** argv) {
	using namespace htool::cli;

    CLIOptions opts = parse(argc, argv);

    if (opts.print_version) {
        info("version " + std::to_string(VERSION_MAJOR) + "." + 
			std::to_string(VERSION_MINOR));
	}

	if (opts.cmd == Command::Make) {
		Container* container = Container::create(
			opts.container, opts.password);
		delete container;
		return EXIT_SUCCESS;
	} else if (opts.cmd == Command::Remove) {
		if (!fs::exists(opts.container))
			fatal("container does not exist: " + opts.container);

		fs::remove(opts.container.c_str());
		return EXIT_SUCCESS;
	}

	Container* container = Container::open(
		opts.container, opts.password);

	if (opts.cmd == Command::Store) {
		for (const std::string& path : opts.paths)
			container->store_file(path);
	}

	if (opts.cmd == Command::Load) {
		for (const std::string& path : opts.paths)
			container->load_file(path);
	}

	if (opts.cmd == Command::Delete) {
		for (const std::string& path : opts.paths)
			if (!container->delete_file(path))
				cli::fatal("failed to delete file from container: " + path);
	}

	if (opts.cmd == cli::Command::List) {
		container->list(opts.container.substr(
			opts.container.find_last_of('/') + 1) + "_ls.txt");
	}

	if (opts.compact)
		container->compact();

	delete container;
	return EXIT_SUCCESS;
}

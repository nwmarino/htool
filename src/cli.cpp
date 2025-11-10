//
// Copyright (c) 2025 Nick Marino
// All rights reserved.
//

//
// cli.cpp
//
// The following source implements the command line interface and parsing 
// thereof for the tool.
//

#include "cli.h"

#include "boost/program_options/options_description.hpp"
#include "boost/program_options/parsers.hpp"
#include "boost/program_options/positional_options.hpp"
#include "boost/program_options/variables_map.hpp"

#include <cstdlib>
#include <iostream>

namespace bpo = boost::program_options;

using namespace htool;
using namespace htool::cli;

cli::CLIOptions cli::parse(int argc, char** argv) {
	// Define the command line options using boost.
	CLIOptions opts;
	bpo::options_description desc { "Options" };
	desc.add_options()
	(
		"help,h", 
		"show help message"
	)
	(
		"make,mk", 
		bpo::value<std::string>(&opts.container), 
		"create a new container"
	)
	(
		"remove,rm", 
		bpo::value<std::string>(&opts.container), 
		"delete a container"
	)
	(
		"password,pw", 
		bpo::value<std::string>(&opts.password), 
		"specify the container password"
	)
	(
		"list,ls", 
		"log the contents of the container"
	)
	(
		"store", 
		bpo::value<std::vector<std::string>>(&opts.paths)->multitoken(), 
		"store files to the container"
	)
	(
		"load", 
		bpo::value<std::vector<std::string>>(&opts.paths)->multitoken(), 
		"load files from the container"
	)
	(
		"delete,del",
		bpo::value<std::vector<std::string>>(&opts.paths)->multitoken(),
		"delete files from the container"
	)
	(
		"compact,c",
		"compact the container file"
	)
	(
		"version,v", 
		"print the version of the program"
	);

	// Add a positional option for the container path.
	bpo::options_description positional_desc { "Positional options" };
	positional_desc.add_options()
	(
		"container",
		bpo::value<std::string>(&opts.container),
		"path to the container"
	);
	
	bpo::positional_options_description positional;
	positional.add("container", 1);

	// Parse the command line arguments.
	bpo::variables_map vmap;
	try {
		bpo::store(
			bpo::command_line_parser(argc, argv)
				.options(desc.add(positional_desc))
				.positional(positional)
				.run(),
			vmap);
		bpo::notify(vmap);

		// If help is requested, print the help message and exit.
		if (vmap.count("help")) {
			std::cout << desc << std::endl;
			std::exit(EXIT_SUCCESS);
		}

		// Enforce password requirement
		if (!vmap.count("password"))
			cli::fatal("password must be specified with --pw or --password");

		opts.password = vmap["password"].as<std::string>();

		// To ensure only one operation is given.
		uint32_t command_count = 0;

		if (vmap.count("make")) {
			command_count++;
			opts.cmd = Command::Make;
			opts.container = vmap["make"].as<std::string>();
		}

		if (vmap.count("remove")) {
			command_count++;
			opts.cmd = Command::Remove;
			opts.container = vmap["remove"].as<std::string>();
		}

		if (vmap.count("store")) {
			command_count++;
			opts.cmd = Command::Store;
			opts.paths = vmap["store"].as<std::vector<std::string>>();
		}

		if (vmap.count("load")) {
			command_count++;
			opts.cmd = Command::Load;
			opts.paths = vmap["load"].as<std::vector<std::string>>();
		}

		if (vmap.count("delete")) {
			command_count++;
			opts.cmd = Command::Delete;
			opts.paths = vmap["delete"].as<std::vector<std::string>>();
		}

		if (vmap.count("compact"))
			opts.compact = true;

		if (vmap.count("list")) {
			command_count++;
			opts.cmd = Command::List;
		}

		// Don't increment command count for version.
		if (vmap.count("version"))
			opts.print_version = true;
		
		// Check that a command was given.
		if (command_count == 0 && !opts.print_version && 
		  !vmap.count("container") && !opts.compact) {
			cli::fatal("no container specified");
		} else if (command_count > 1) { // Check only one command was given.
			cli::fatal("multiple commands specified");
		} else if ((opts.cmd != Command::Make && opts.cmd != Command::Remove) 
		  && !vmap.count("container")) { // Check a container path was given.
			cli::fatal("no container path specified");
		}
	} catch (const bpo::error& e) {
		std::cerr << "htool: argument parsing error: " << e.what() << std::endl;
		std::cout << desc << std::endl;
		exit(EXIT_FAILURE);
	} catch (const std::runtime_error& e) {
		std::cerr << e.what() << std::endl;
		std::cout << desc << std::endl;
		exit(EXIT_FAILURE);
	}

	return opts;
}

void cli::info(const std::string& msg) { 
	std::cerr << "htool: " << msg << '\n'; 
}

void cli::fatal(const std::string& msg) {
  	std::cerr << "htool: " << msg << std::endl;
  	std::exit(EXIT_FAILURE);
}

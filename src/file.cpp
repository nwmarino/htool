//
// Copyright (c) 2025 Nick Marino
// All rights reserved.
//

//
// file.cpp
//
// The following source implements some basic file i/o operations.
//

#include "cli.h"
#include "file.h"

#include <fstream>

using namespace htool;

std::vector<unsigned char> htool::read_file(const std::string& path) {
  	// Attempt to open the file for reading.
  	std::ifstream file(path, std::ios::binary | std::ios::ate);
	if (!file || !file.is_open())
		cli::fatal("htool: file does not exist: " + path);

	// Fetch the size of the file contents.
	std::streamsize size = file.tellg();
	file.seekg(0, std::ios::beg);

	// Instantiate a buffer and attempt to read the contents to it.
	std::vector<unsigned char> buffer(size);
	if (!file.read(reinterpret_cast<char*>(buffer.data()), size))
		cli::fatal("htool: cannot read contents of file: " + path);

	// Close the file and return its contents.
	file.close();
	return buffer;
}

void htool::write_file_binary(
		const std::string& path, const std::vector<unsigned char>& data) {
  	// Attempt to open the file for binary writing.
  	std::ofstream file(path, std::ios::binary);
  	if (!file || !file.is_open())
    	cli::fatal("htool: unable to create or access file: " + path);

  	// Attempt to write the given data to the file.
  	if (!file.write(reinterpret_cast<const char*>(data.data()), data.size()))
    	cli::fatal("htool: cannot write to file: " + path);

  	file.close();
}

//
// Copyright (c) 2025 Nick Marino
// All rights reserved.
//

//
// fat.cpp
//
// The following source implements serialization procedures for file allocation
// table entries.
//

#include "cli.h"
#include "fat.h"
#include "encryption.h"

#include "boost/filesystem/operations.hpp"

namespace fs = boost::filesystem;

using namespace htool;

void htool::get_metadata(const std::string& path, FATEntry& entry) {
    if (!fs::exists(path))
        cli::fatal("htool: file does not exist: " + path);

  	// Construct a new FAT entry given the file.
	entry.filename = fs::path(path).filename().string();
	entry.original_size = fs::file_size(path);
	entry.encrypted_size = 0;
	entry.compressed_size = 0;
	entry.last_modified = fs::last_write_time(path);
	entry.checksum = compute_checksum(path);
}

void htool::serialize(std::ostringstream& os, const FATEntry& entry) {
  	if (entry.filename.size() > MAX_FILENAME_LENGTH)
    	cli::fatal("htool: filename too long: " + entry.filename);

	// Create a filename padded to 32 bytes, and write it.
	std::string padded_filename = entry.filename;
	padded_filename.resize(32, '\0');
	os.write(padded_filename.data(), 32);
	
	// Write the original, compressed, and encrypted sizes.
	os.write(
		reinterpret_cast<const char *>(&entry.original_size), 
		sizeof(entry.original_size));
	os.write(
		reinterpret_cast<const char *>(&entry.compressed_size), 
		sizeof(entry.compressed_size));
	os.write(
		reinterpret_cast<const char *>(&entry.encrypted_size), 
		sizeof(entry.encrypted_size));

	// Write the offset.
	os.write(
		reinterpret_cast<const char *>(&entry.offset),
		sizeof(entry.offset));

	// Write the last modified timestamp.
	long last_modified_time = static_cast<long>(entry.last_modified);
	os.write(
		reinterpret_cast<const char *>(&last_modified_time), 
		sizeof(last_modified_time));
	
	// Write the IV, checksum.
	os.write(
		reinterpret_cast<const char*>(entry.iv.data()), 
		entry.iv.size());
	os.write(
		reinterpret_cast<const char*>(entry.checksum.data()), 
		entry.checksum.size());
}

bool htool::deserialize(std::istringstream& is, FATEntry& entry) {
	try {
		// Read in the filename.
		char filename_buf[MAX_FILENAME_LENGTH] = {};
		is.read(filename_buf, MAX_FILENAME_LENGTH);
		if (is.gcount() != MAX_FILENAME_LENGTH)
			return false;

		// Convert buffer to string, trimming padding.
		entry.filename = std::string(filename_buf);

		// Read in the original, compressed, and encrypted sizes.
		is.read(
			reinterpret_cast<char*>(&entry.original_size),
			sizeof(entry.original_size));
		is.read(
			reinterpret_cast<char*>(&entry.compressed_size), 
			sizeof(entry.compressed_size));
		is.read(
			reinterpret_cast<char*>(&entry.encrypted_size), 
			sizeof(entry.encrypted_size));
		
		// Read in the offset.
		is.read(
			reinterpret_cast<char*>(&entry.offset), sizeof(entry.offset));

		// Read in the last modified timestamp.
		uint64_t last_modified;
		is.read(
			reinterpret_cast<char *>(&last_modified), sizeof(last_modified));
		entry.last_modified = static_cast<std::time_t>(last_modified);

		// Read in the IV, checksum.
		is.read(
			reinterpret_cast<char *>(entry.iv.data()), entry.iv.size());
		is.read(
			reinterpret_cast<char *>(entry.checksum.data()), entry.checksum.size());

		return true;
	} catch(...) {
		return false;
	}
}

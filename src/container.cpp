//
// Copyright (c) 2025 Nick Marino
// All rights reserved.
//

//
// container.cpp
//
// The following source implements the Container class and its respective
// methods.
//

#include "cli.h"
#include "common.h"
#include "container.h"
#include "encryption.h"
#include "fat.h"
#include "file.h"

#include "boost/filesystem/operations.hpp"
#include "boost/iostreams/filtering_stream.hpp"
#include "boost/iostreams/filter/zlib.hpp"
#include "openssl/evp.h"

#include <algorithm>
#include <cstdint>
#include <iomanip>
#include <iostream>

namespace fs = boost::filesystem;
namespace ios = boost::iostreams;

using namespace htool;

//! Default number of iterations to use for PBKDF2.
constexpr std::size_t PBKDF2_ITERATIONS = 100000;

//! Default chunk size for container compaction.
constexpr std::size_t CHUNK_SIZE = 1024 * 128;

//! Container layout:
//!
//! [reserved space : 32768 bytes = 32KB]
//! [files : ...]
//!
//! Reserved space layout:
//!
//! 0  | [version : 4]
//! 4  | [master salt : 16]
//! 20 | [master hash : 32]
//! 52 | [FAT IV : 16]
//! 68 | [FAT size : 8]
//! 76 | [FAT entries : -32692]
constexpr std::size_t RESERVED_SPACE = 32768;
constexpr std::size_t WIDTH_VERSION = 4;
constexpr std::size_t WIDTH_SIZE = 8;
constexpr std::size_t WIDTH_IV = 16;
constexpr std::size_t WIDTH_SALT = 16;
constexpr std::size_t WIDTH_HASH = 32;

//! Constant offsets for the reserved container layout.
constexpr std::size_t OFFSET_VERSION = 0;
constexpr std::size_t OFFSET_MASTER_SALT = OFFSET_VERSION + WIDTH_VERSION;
constexpr std::size_t OFFSET_MASTER_HASH = OFFSET_MASTER_SALT + WIDTH_SALT;
constexpr std::size_t OFFSET_FAT_IV = OFFSET_MASTER_HASH + WIDTH_HASH;
constexpr std::size_t OFFSET_FAT_SIZE = OFFSET_FAT_IV + WIDTH_IV;
constexpr std::size_t OFFSET_FAT = OFFSET_FAT_SIZE + WIDTH_SIZE;

Container::Container(const std::string& path, const std::string& pw) 
    	: m_path(path), m_name(path.substr(path.find_last_of('/') + 1)) {
    if (!fs::exists(m_path))
      	cli::fatal("does not exist: " + m_name);

	m_container.open(
		m_path, std::ios::binary | std::ios::in | std::ios::out);

	if (!m_container || !m_container.is_open())
		cli::fatal("failed to open: " + m_name);

	// Check the version.
	load_version();

	// Load the stored master hash and compare it to the input password.
	load_master();
	if (!match_password(pw, m_master, m_salt)) {
		m_container.close();
		std::fill(m_salt.begin(), m_salt.end(), 0);
		std::fill(m_master.begin(), m_master.end(), 0);
		cli::fatal("incorrect password: " + pw);
	}

	// Derive the encryption key from the password.
	std::array<unsigned char, 32> derived_tmp;
	if (!PKCS5_PBKDF2_HMAC(
		pw.c_str(),
		pw.length(),
		m_salt.data(),
		WIDTH_SALT,
		PBKDF2_ITERATIONS,
		EVP_sha256(),
		WIDTH_HASH,
		derived_tmp.data())
	) {
		cli::fatal("failed to derive encryption key: " + m_name);
	}

	m_key = derived_tmp;

	// Clear the salt, master hash from memory.
	std::fill(m_salt.begin(), m_salt.end(), 0);
	std::fill(m_master.begin(), m_master.end(), 0);
	std::fill(derived_tmp.begin(), derived_tmp.end(), 0);

	load_fat(); // Load the FAT from the container.
}

Container::Container(const std::string& name, const std::string& path,
                     const std::string& pw) : m_name(name), m_path(path) {
  	if (fs::exists(m_path))
    	cli::fatal("container already exists with name: " + name);

	// Create the new container.
	m_container.open(
		m_path,
		std::ios::binary | std::ios::in | std::ios::out | std::ios::trunc);

  	if (!m_container.is_open())
    	cli::fatal("failed to open container: " + name);

	// Check that the current version is valid to store.
	const std::string major_str = std::to_string(VERSION_MAJOR);
	if (major_str.size() > 2)
		cli::fatal("invalid version, major too large: " + major_str);

	const std::string minor_str = std::to_string(VERSION_MINOR);
	if (minor_str.size() > 2)
		cli::fatal("invalid version, minor too large: " + minor_str);

	m_version.at(0) = std::string(major_str).c_str()[0];
	m_version.at(1) = std::string(major_str).c_str()[1];
	m_version.at(2) = std::string(minor_str).c_str()[0];
	m_version.at(3) = std::string(minor_str).c_str()[1];
	store_version();

	// Hash the master password and store it to the container.
	m_salt = generate_rand(WIDTH_SALT);
	m_master = hash_password(pw, m_salt);

	// Derive the encryption key from the password.
	std::array<unsigned char, 32> derived_tmp;
	if (!PKCS5_PBKDF2_HMAC(
		pw.c_str(),
		pw.length(),
		m_salt.data(),
		WIDTH_SALT,
		PBKDF2_ITERATIONS,
		EVP_sha256(),
		WIDTH_HASH,
		derived_tmp.data())
	) {
		cli::fatal("failed to derive encryption key for container: " + name);
	}

  	m_key = derived_tmp;
  	store_master(); // Clears salt, master from memory.

  	// Write the remaining reserved space as empty.
  	std::vector<unsigned char> empty_space(
		RESERVED_SPACE - m_container.tellp(), 0);
  	if (!m_container.write(
    	reinterpret_cast<const char *>(empty_space.data()), empty_space.size())
	) {
    	cli::fatal("failed to allocate space for container: " + name);
  	}
}

Container::~Container() {
	store_fat();

	// Ensure all sensitive data is wiped from memory.
	std::fill(m_salt.begin(), m_salt.end(), 0);
	std::fill(m_master.begin(), m_master.end(), 0);
	std::fill(m_key.begin(), m_key.end(), 0);
	m_fat.clear();

	// Close the container file.
	m_container.close(); 
}

Container* Container::create(const std::string& path, const std::string& pw) { 
	return new Container(path.substr(path.find_last_of('/') + 1), path, pw);
}

Container* Container::open(const std::string& path, const std::string& pw) { 
	return new Container(path, pw); 
}

//! Writes Container::m_version to the container.
//!
//! This method should only ever be called by the opening constructor, as after
//! creation, a version should be immutable.
void Container::store_version() {
  	// Clear the container position for writing.
  	m_container.clear();
  	m_container.seekp(OFFSET_VERSION, std::ios::beg);

  	// Write the version to the container.
  	if (!m_container.write(
    	reinterpret_cast<const char*>(m_version.data()), WIDTH_VERSION)
	) {
    	cli::fatal("failed to write version for container: " + m_name);
  	}

  	// Flush the container to ensure the version is written.
  	if (!m_container.flush())
    	cli::fatal("failed to flush stream for container: " + m_name);
}

void Container::load_version() {
	// Clear the container position for reading.
	m_container.clear();
	m_container.seekg(OFFSET_VERSION, std::ios::beg);

	// Attempt to read the version from the container.
	if (!m_container.read(
		reinterpret_cast<char*>(m_version.data()), WIDTH_VERSION)
	) {
		cli::fatal("failed to read htool version from container: " + m_name);
	}

	// Stringify the current version of the program.
	const std::string major_str = std::to_string(VERSION_MAJOR);
	const std::string minor_str = std::to_string(VERSION_MINOR);
	std::array<unsigned char, 4> curr_version_str;
	curr_version_str.at(0) = std::string(major_str).c_str()[0];
	curr_version_str.at(1) = std::string(major_str).c_str()[1];
	curr_version_str.at(2) = std::string(minor_str).c_str()[0];
	curr_version_str.at(3) = std::string(minor_str).c_str()[1];

	// Check that the versions match.
	bool versions_match = std::string(m_version.begin(), m_version.end()) == 
		std::string(curr_version_str.begin(), curr_version_str.end());
	if (!versions_match) {
		// Stringify the read in version.
		std::string container_version_str;
		container_version_str.push_back(m_version.at(0));
		container_version_str.push_back(m_version.at(1));
		container_version_str.push_back('.');
		container_version_str.push_back(m_version.at(2));
		container_version_str.push_back(m_version.at(3));
		
		cli::fatal("current version (" + std::to_string(VERSION_MAJOR) + '.' + 
			std::to_string(VERSION_MINOR) + ") incompatible with container: " + 
			m_name + ", expected " + container_version_str);
	}
}

//! Writes Container::m_master to a container.
//!
//! This function writes the master password hash with a new salt to the 
//! container on the following byte layout:
//!
//! [salt : 16][hash : 32] ...
//!
//! This function also clears the stored salt & hash from container memory.
void Container::store_master() {
	// Clear the container positioning for writing.
	m_container.clear();
	m_container.seekp(OFFSET_MASTER_SALT, std::ios::beg);

	// Write the salt at its offset.
	assert(m_container.tellp() == OFFSET_MASTER_SALT);
	if (!m_container.write(
		reinterpret_cast<char*>(m_salt.data()), WIDTH_SALT)
	) {
		cli::fatal("failed to write salt to container: " + m_name);
	}

	// Write the password hash at its offset.
	assert(m_container.tellp() == OFFSET_MASTER_HASH);
	if (!m_container.write(
		reinterpret_cast<char*>(m_master.data()), WIDTH_HASH)
	) {
		cli::fatal("failed to write hash to container: " + m_name);
	}

	// Clear the stored salt, hash from memory.
	std::fill(m_salt.begin(), m_salt.end(), 0);
	std::fill(m_master.begin(), m_master.end(), 0);
}

//! Reads a container salt and hash to Container::m_master.
//!
//! The function reads on the following byte layout:
//!
//! [salt : 16][hash : 32] ...
//!
void Container::load_master() {
	// Clear the container positioning for reading.
	m_container.clear();
	m_container.seekg(OFFSET_MASTER_SALT, std::ios::beg);

	// Read the stored salt.
	std::vector<unsigned char> tmp_salt(WIDTH_SALT);
	assert(m_container.tellg() == OFFSET_MASTER_SALT);
	if (!m_container.read(
		reinterpret_cast<char*>(tmp_salt.data()), tmp_salt.size())
	) {
		cli::fatal("failed to read salt from container: " + m_name);
	}

	// Read the stored hash.
	std::vector<unsigned char> tmp_hash(WIDTH_HASH);
	assert(m_container.tellg() == OFFSET_MASTER_HASH);
	if (!m_container.read(
		reinterpret_cast<char*>(tmp_hash.data()), tmp_hash.size())
	) {
		cli::fatal("failed to read hash from container: " + m_name);
	}

	// Copy the temp. salt, hash to the container and clear them from memory.
	m_salt = tmp_salt;
	m_master = tmp_hash;
	std::fill(tmp_salt.begin(), tmp_salt.end(), 0);
	std::fill(tmp_hash.begin(), tmp_hash.end(), 0);
}

//! Stores the current state of the FAT to the container.
//!
//! This method does not modify the current FAT state.
void Container::store_fat() {
	// Clear the container positioning for writing.
	m_container.clear();
	m_container.seekp(OFFSET_FAT_IV, std::ios::beg);
	if (!m_container) {
		cli::fatal("failed to update file allocation table for container: " + 
			m_name);
	}

	// Attempt to write a new IV for the FAT.
	std::array<unsigned char, 16> iv = generate_iv();
	if (!m_container.write(
		reinterpret_cast<const char*>(iv.data()), WIDTH_IV)
	) {
		cli::fatal("failed to store fat allocation table IV for container: " + 
			m_name);
	}

	// Serialize all FAT entries and stringify the stream.
	std::ostringstream fat_stream;
	for (const FATEntry& entry : m_fat)
		serialize(fat_stream, entry);

	const std::string serialized_fat = fat_stream.str();

	// Encrypt the serialized FAT.
	std::vector<unsigned char> enc_fat = aes_encrypt(
		std::vector<unsigned char>(serialized_fat.begin(), serialized_fat.end()), 
		m_key,
		iv);

	// Write the size of the encrypted FAT to the container.
	const uint64_t size = enc_fat.size();
	m_container.seekp(OFFSET_FAT_SIZE, std::ios::beg);
	if (!m_container.write(
		reinterpret_cast<const char*>(&size), WIDTH_SIZE)
	) {
		cli::fatal("failed to store file allocation table size to container: " + 
			m_name);
	}

	// Write the encrypted FAT to the container.
	if (!m_container.write(
		reinterpret_cast<const char *>(enc_fat.data()), enc_fat.size())
	) {
		cli::fatal("failed to update file allocation table: " + m_name);
	}

	// Flush the container to ensure the FAT is written.
	if (!m_container.flush())
		cli::fatal("failed to flush stream for container: " + m_name);
}

//! Loads the stored container FAT to memory.
//!
//! This method does not modify the stored FAT state.
void Container::load_fat() {
	// Clear the container positioning for reading.
	m_container.clear();
	m_container.seekg(OFFSET_FAT_IV, std::ios::beg);
	if (!m_container) {
		cli::fatal("failed to find file allocation table in container: " + 
			m_name);
	}

	// Read the IV for the FAT.
	std::array<unsigned char, 16> iv;
	if (!m_container.read(
		reinterpret_cast<char *>(iv.data()), WIDTH_IV)
	) {
		cli::fatal("failed to load file allocation table IV from container: " + 
			m_name);
	}

	// Read the size of the encrypted FAT.
	uint64_t size;
	m_container.seekg(OFFSET_FAT_SIZE, std::ios::beg);
	if (!m_container.read(
		reinterpret_cast<char *>(&size), WIDTH_SIZE)
	) {
		cli::fatal("failed to load file allocation table size from container: " + 
			m_name);
	}

	// Read the encrypted FAT from the container.
	std::vector<unsigned char> enc_fat(size);
	if (!m_container.read(
		reinterpret_cast<char *>(enc_fat.data()), 
		enc_fat.size()
	)) {
		cli::fatal("failed to load file allocation table from container: " + 
			m_name);
	}

	// Check if the number of entries read matches the expected count.
	if (m_container.gcount() != size) {
		cli::fatal("failed to load full file allocation table from container: " + 
			m_name);
	}

	std::vector<unsigned char> dec_fat = aes_decrypt(enc_fat, m_key, iv);

	// Initialize a string stream to deserialize the decrypted FAT.
	std::istringstream fat_stream(std::string(dec_fat.begin(), dec_fat.end()));

	// Clear the FAT and attempt to read deserialized entries from the stream.
	m_fat.clear();
	while (fat_stream) {
		FATEntry entry;
		if (deserialize(fat_stream, entry))
			m_fat.push_back(entry);
	}
}

bool Container::delete_file(const std::string &path) {
	// Check if the file exists in the FAT.
	auto it = std::find_if(
		m_fat.begin(), 
		m_fat.end(), 
		[&path](const FATEntry& entry) -> bool {
			return entry.filename == path;
		}
	);

	if (it == m_fat.end()) 
		return false;

	const uint64_t offset = it->offset;
	const uint64_t size = it->encrypted_size;

	// Clear the file data from the container.
	m_container.seekp(offset, std::ios::beg);
	std::vector<unsigned char> empty_data(size, 0);
	if (!m_container.write(
		reinterpret_cast<const char *>(empty_data.data()), empty_data.size())
	) {
		cli::fatal("failed to clear file data: " + m_name);
	}

	m_fat.erase(it); // Remove the file from the FAT.
	return true;
}

//! Dumps metadata for each FAT entry to the file at path.
//!
//! This function loads the FAT into container memory and does not clear it.
void Container::list(const std::string& path) {
  	// Attempt to open the dump file.
  	std::ofstream output(path);
  	if (!output || !output.is_open())
		cli::fatal("failed to open output file: " + path);

	// Write a formatted header.
	output << std::left << std::setw(30) << "Filename" << std::setw(15) << 
		"Original Size" << std::setw(25) << "Last Modified" << '\n';

	// Write a separator line.
	output << std::string(58, '-') << '\n';

	// Dump each FAT entry to the output file.
	for (const FATEntry& entry : m_fat) {
		// Convert the integer timestamp to a formatted timestamp.
		std::tm *time_info = std::gmtime(&entry.last_modified);
		if (!time_info)
			cli::fatal("failed to convert timestamp to a string");

		// Stringify the timestamp.
		std::ostringstream timestamp_str;
		timestamp_str << std::put_time(time_info, "%Y-%m-%d %H:%M:%S");

		// Write the entry metadata to the text file.
		output << std::setw(30) << entry.filename << std::setw(15) << 
			entry.original_size << std::setw(25) << timestamp_str.str() << 
			'\n';
	}

	output.close();
}

void Container::compact() {
	if (m_fat.empty())
		return;

	// Create a temporary container file to read compacted data into.
	const std::string tmp_file = m_path + ".tmp";
	std::ofstream tmp_container(tmp_file, std::ios::binary | std::ios::out);
	if (!tmp_container || !tmp_container.is_open())
		cli::fatal("failed to create temporary container: " + m_name);

	// Reserve space in the new container.
	tmp_container.seekp(RESERVED_SPACE - 1, std::ios::beg);
	tmp_container.write("", 1);

	// For each FAT entry, write its data in chunks to the new container.
	std::streampos new_offset = RESERVED_SPACE;
	for (FATEntry& entry : m_fat) {
		// Instantiate a buffer to read file data in chunks.
		std::vector<unsigned char> buffer(CHUNK_SIZE);
		m_container.seekg(entry.offset, std::ios::beg);
		std::size_t remaining = entry.encrypted_size;
		std::streampos new_entry_offset = new_offset;

		// Repeat until all data is read.
		while (remaining > 0) {
			std::size_t to_read = std::min(CHUNK_SIZE, remaining);
			m_container.read(reinterpret_cast<char*>(buffer.data()), to_read);
			if (m_container.gcount() != to_read)
				cli::fatal("failed to read data from container");

			if (!tmp_container.write(
				reinterpret_cast<char*>(buffer.data()), to_read)
			) {
				cli::fatal("failed to write data to temporary container");
			}

			remaining -= to_read;
			new_offset += to_read;
		}

		// Update the file's FAT entry offset.
		entry.offset = new_entry_offset;
	}

	// Close the temporary file.
	m_container.close();
	tmp_container.close();

	if (!fs::remove(m_path.c_str()))
		cli::fatal("failed to remove original container file");

	fs::rename(tmp_file, m_path);

	// Reopen the container file.
	m_container.open(m_path, std::ios::binary | std::ios::in | std::ios::out);
}

bool Container::contains(const std::string& name) const {
	return std::find_if(
		m_fat.begin(), 
		m_fat.end(), 
		[&name](const FATEntry& entry) -> bool {
			return entry.filename == name;
		}
	) != m_fat.end();
}

FATEntry& Container::get_entry(const std::string& name) const {
	auto it = std::find_if(
		m_fat.begin(), 
		m_fat.end(), 
		[&name](const FATEntry& entry) -> bool {
			return entry.filename == name;
		}
	);

	if (it == m_fat.end())
		cli::fatal("unresolved file in container: " + name);

	return const_cast<FATEntry&>(*it);
}

void Container::store_file(const std::string& path) {
	std::vector<unsigned char> contents = read_file(path);

	// Compress file data.
	std::stringstream compressed_stream;
	{
		ios::filtering_ostream out;
		out.push(ios::zlib_compressor());
		out.push(compressed_stream);
		out.write(reinterpret_cast<const char*>(contents.data()), contents.size());
		out.flush();
	}

	// Stringify the compressed stream data.
	std::string compressed_data_str = compressed_stream.str();
	std::vector<unsigned char> compressed_data(
		compressed_data_str.begin(), 
		compressed_data_str.end()
	);

	// Generate an IV for this file and encrypt its compressed data.
	std::array<unsigned char, 16> iv = generate_iv();
	std::vector<unsigned char> enc_data = aes_encrypt(
		compressed_data, m_key, iv);

	// If an entry exists, update it.
	if (contains(path) || contains(path.substr(path.find_last_of('/') + 1))) {
		FATEntry& existing = get_entry(path);
		existing.original_size = contents.size();
		existing.compressed_size = compressed_data.size();
		existing.encrypted_size = enc_data.size();
		existing.last_modified = fs::last_write_time(path);
		existing.iv = iv;
		existing.checksum = compute_checksum(path);

		// Reuse existing space if the new entry is smaller.
		if (existing.encrypted_size >= enc_data.size()) {
			m_container.seekp(existing.offset, std::ios::beg);
			if (!m_container.write(
				reinterpret_cast<const char *>(enc_data.data()), 
				enc_data.size())
			) {
				cli::fatal("failed to overwrite encrypted file: " + m_name);
			}
		} else {
			// Append to the end of the container.
			m_container.seekp(0, std::ios::end);
			existing.offset = m_container.tellp();
			if (!m_container.write(
				reinterpret_cast<const char *>(enc_data.data()), 
				enc_data.size()
			)) {
				cli::fatal("failed to store encrypted file: " + m_name);
			}
		}
	} else {
		// Append a new entry to the table.
		FATEntry entry = {};
		entry.filename = path;
		entry.original_size = contents.size();
		entry.compressed_size = compressed_data.size();
		entry.encrypted_size = enc_data.size();
		entry.iv = iv;
		entry.last_modified = fs::last_write_time(path);
		entry.checksum = compute_checksum(path);

		// Seek to the end of the container to append the new file.
		m_container.seekp(0, std::ios::end);
		entry.offset = m_container.tellp();

		// Attempt to store the file.
		if (!m_container.write(
			reinterpret_cast<const char*>(enc_data.data()), enc_data.size())
		) {
			cli::fatal("failed to store new encrypted file: " + m_name);
		}

		m_fat.push_back(entry);
	}
}

void Container::load_file(const std::string& path) {
	// Attempt to get the FAT entry for the output path. Will fatal if unresolved.
	const FATEntry& entry = get_entry(path);

	// Attempt to read target file data from its offset.
	m_container.seekg(entry.offset, std::ios::beg);
	std::vector<unsigned char> enc_data(entry.encrypted_size);
	m_container.read(
		reinterpret_cast<char *>(enc_data.data()), 
		enc_data.size()
	);

	// Check that the read data matches the expected size.
	if (m_container.gcount() != static_cast<std::streamsize>(entry.encrypted_size))
		cli::fatal("failed to read encrypted data from container: " + m_name);

	// Decrypt the read file data.
	std::vector<unsigned char> dec_data = aes_decrypt(
		enc_data, m_key, entry.iv);

	// Decompress the decrypted data.
	std::stringstream dec_stream(std::string(dec_data.begin(), dec_data.end()));
	ios::filtering_istream in;
	in.push(ios::zlib_decompressor());
	in.push(dec_stream);

	// Read the decompressed data from the stream.
	std::vector<unsigned char> file_data;
	while (in) {
		char buffer[1024];
		in.read(buffer, sizeof(buffer));
		file_data.insert(file_data.end(), buffer, buffer + in.gcount());
	}

	// Compare the checksum.
	if (compute_checksum(file_data) != entry.checksum) {
		cli::fatal("checksum mismatch: " + path);
	} else {
		cli::info("[load_file] " + path + " checksum matches!");
	}

	// Create the decrypted file at the output path.
	write_file_binary(path, file_data);
}

//
// Copyright (c) 2025 Nick Marino
// All rights reserved.
//

//
// container.h
//
// This header file defines the container abstraction, which represents a
// container instance. The primary responsibility of the class is to make 
// actions like storing/loading files easier.
//

#ifndef HTOOL_CONTAINER_H_
#define HTOOL_CONTAINER_H_

#include "fat.h"

#include <array>
#include <fstream>
#include <string>
#include <vector>

namespace htool {

class Container {
	//! The name of the container.
	const std::string m_name;

	//! The path to the container.
	const std::string& m_path;

	//! The current version of the container. This is fetched to track possible
	//! incompatibilities between container and htool versions.
	std::array<unsigned char, 4> m_version = {};

	//! The salt used to hash the master password.
	std::vector<unsigned char> m_salt = {};

	//! The hashed master password of the container.
	std::vector<unsigned char> m_master = {};

	//! The derived encryption key.
	std::array<unsigned char, 32> m_key = {};

	//! The file i/o stream for reading/writing to the container file.
	std::fstream m_container;

	//! The file allocation table of the container.
	std::vector<FATEntry> m_fat = {};

	//! Create a new container representation based on an existing container.
	//! The new instance is based on the container file at |path| and is
	//! decrypted with the plain password |pw|.
	Container(const std::string& path, const std::string& pw);

	//! Create a new container with the given name, at |path| with the plain
	//! password |pw|.
	Container(const std::string& name, const std::string& path,
			  const std::string& pw);

	//! Writes the version to the container.
	void store_version();

	//! Loads the version from the container.
	void load_version();

	//! Writes the current master hash to the container.
	void store_master();

	//! Loads the master hash from the container.
	void load_master();

public:
	Container(const Container&) = delete;
	Container& operator = (const Container&) = delete;

	Container(Container&&) noexcept = delete;
	Container& operator = (Container&&) noexcept = delete;

	~Container();

	//! Create a new container at |path| with the password |pw|.
	[[nodiscard]]
	static Container* create(const std::string& path, const std::string& pw);

	//! Opens an existing container at the given path with password |pw|.
	[[nodiscard]]
	static Container* open(const std::string& path, const std::string& pw);

	//! Writes the current state of the file allocation table to the container.
	void store_fat();

	//! Loads the current state of the file allocation table from the container.
	void load_fat();

	//! Returns true if this container contains a file with the given name.
	bool contains(const std::string& name) const;

	//! Returns the file allocation table entry for the file with the given name.
	FATEntry& get_entry(const std::string& name) const;

	//! Stores the file at |path| to this container.
	void store_file(const std::string& path);

	//! Loads the file with |path| from this container.
	void load_file(const std::string& path);

	//! Attempt to delete the file at |path| from this container and its
	//! corresponding entry in the file allocation table. Returns true if the
	//! deletion was successful, and false otherwise.
	bool delete_file(const std::string& path);

	//! Lists the internal file contents of this container to |path|.
	void list(const std::string& path);

	//! Compact this container by overwriting empty space.
	void compact();

	//! Returns the file allocation table of this container.
	const std::vector<FATEntry>& get_fat() const { return m_fat; }
	std::vector<FATEntry>& get_fat() { return m_fat; };
};

} // namespace htool

#endif // HTOOL_CONTAINER_H_

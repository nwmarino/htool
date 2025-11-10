//
// Copyright (c) 2025 Nick Marino
// All rights reserved.
//

//
// fat.h
//
// This header file defines the structure type for entries in the file
// allocation table of a container, which help track the metadata of encrypted
// files.
//

#ifndef HTOOL_FAT_H_
#define HTOOL_FAT_H_

#include <array>
#include <cstdint>
#include <ctime>
#include <sstream>
#include <string>

namespace htool {

constexpr uint32_t MAX_FILENAME_LENGTH = 32;

//! FAT metadata for a file entry.
struct FATEntry {
    std::string filename;
    uint64_t original_size;
    uint64_t encrypted_size;
    uint64_t compressed_size;
    uint64_t offset;
    time_t last_modified;
    std::array<unsigned char, 16> iv;
    std::array<unsigned char, 32> checksum;
};

//! Writes the metadata associated with the file at |path| to the given FAT
//! entry.
void get_metadata(const std::string& path, FATEntry& entry);

//! Serializes the given fat entry to the output stream |os|.
void serialize(std::ostringstream& os, const FATEntry& entry);

//! Deserializes the given fat entry from the input stream |is|. Returns false 
//! if an entry could not deserialized, and true if the operation worked.
bool deserialize(std::istringstream& is, FATEntry& entry);

} // namespace htool

#endif // HTOOL_FAT_H_

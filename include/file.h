//
// Copyright (c) 2025 Nick Marino
// All rights reserved.
//

//
// file.h
//
// This header file declares basic utility functions related to file i/o.
//

#ifndef HTOOL_FILE_H_
#define HTOOL_FILE_H_

#include <string>
#include <vector>

namespace htool {

//! Returns the contents of the file at |path|.
std::vector<unsigned char> read_file(const std::string& path);

//! Writes the binary data of |data| to the file at |path|.
void write_file_binary(const std::string& path, 
					   const std::vector<unsigned char>& data);

} // namespace htool

#endif // HTOOL_FILE_H_

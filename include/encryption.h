//
// Copyright (c) 2025 Nick Marino
// All rights reserved.
//

//
// encryption.h
//
// This header file defines reusable functions used to encrypt and hash data.
//

#ifndef HTOOLS_ENCRYPTION_H_
#define HTOOLS_ENCRYPTION_H_

#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace htool {

//! Generates a random byte vector of length |len|.
std::vector<unsigned char> generate_rand(const std::size_t len = 32);

//! Generates a random 16-byte initialization vector.
std::array<unsigned char, 16> generate_iv();

//! Generates a random 32-byte encryption key.
std::array<unsigned char, 32> generate_key();

//! Computes and returns the SHA-256 checksum of the file at |path|.
std::array<unsigned char, 32> 
compute_checksum(const std::string& path);

//! Computes and returns the SHA-256 checksum of the |data| vector.
std::array<unsigned char, 32> 
compute_checksum(const std::vector<unsigned char> &data);

//! Encrypts the given data with AES-256-CBC using the 32-byte encryption key 
//! |key| and 16-byte initialization vector |iv|.
std::vector<unsigned char> 
aes_encrypt(const std::vector<unsigned char>& data,
            const std::array<unsigned char, 32>& key,
            const std::array<unsigned char, 16>& iv);

//! Decrypts the given data with AES-256-CBC using the 32-byte encryption key
//! |key| and 16-byte initialization vector |iv|.
std::vector<unsigned char> 
aes_decrypt(const std::vector<unsigned char>& data,
            const std::array<unsigned char, 32>& key,
            const std::array<unsigned char, 16>& iv);

//! Hashes the plaintext password |hash| with salt |salt|, iteration count 
//! |iterations|, and desired hash length |len|.
std::vector<unsigned char> 
hash_password(const std::string& data, const std::vector<unsigned char>& salt,
              const uint32_t iterations = 100000, const uint32_t len = 32);

//! Attempts to match the password |pw| with the given hash.
bool 
match_password(const std::string& pw, const std::vector<unsigned char>& hash,
               const std::vector<unsigned char>& salt);

} // namespace htool

#endif // HTOOLS_ENCRYPTION_H_

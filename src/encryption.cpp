//
// Copyright (c) 2025 Nick Marino
// All rights reserved.
//

//
// encryption.cpp
//
// The following source implements important AES-256 encryption routines
// and password hashing helpers.
//

#include "cli.h"
#include "encryption.h"
#include "file.h"

#include "boost/filesystem/operations.hpp"
#include "openssl/err.h"
#include "openssl/evp.h"
#include "openssl/rand.h"
#include "openssl/sha.h"

#include <cstdint>

namespace fs = boost::filesystem;

using namespace htool;

std::vector<unsigned char> htool::generate_rand(const std::size_t len) {
    std::vector<unsigned char> rand(len);
    if (!RAND_bytes(rand.data(), rand.size()))
        cli::fatal("htool: failed to generate random byte vector");

    return rand;
}

std::array<unsigned char, 16> htool::generate_iv() {
	std::array<unsigned char, 16> iv;
	if (!RAND_bytes(iv.data(), iv.size()))
		cli::fatal("htool: failed to generate randomized initialiation vector");

	return iv;
}

std::array<unsigned char, 32> htool::generate_key() {
	std::array<unsigned char, 32> key;
	if (!RAND_bytes(key.data(), key.size()))
		cli::fatal("htool: failed to generate randomized encryption key");

	return key;
}

std::array<unsigned char, 32> htool::compute_checksum(const std::string& path) {
  	if (!fs::exists(path))
    	cli::fatal("htool: file does not exist: " + path);

	std::vector<unsigned char> data = read_file(path);
	unsigned char hash[SHA256_DIGEST_LENGTH];
	SHA256(data.data(), data.size(), hash);

	// Copy the hash to a fixed-size array.
	std::array<unsigned char, 32> checksum;
	std::copy(hash, hash + SHA256_DIGEST_LENGTH, checksum.begin());
	return checksum;
}

std::array<unsigned char, 32> 
htool::compute_checksum(const std::vector<unsigned char>& data) {
	unsigned char hash[SHA256_DIGEST_LENGTH];
	SHA256(data.data(), data.size(), hash);

	// Copy the hash to a fixed-size array.
	std::array<unsigned char, 32> checksum;
	std::copy(hash, hash + SHA256_DIGEST_LENGTH, checksum.begin());
	return checksum;
}

std::vector<unsigned char>
htool::aes_encrypt(const std::vector<unsigned char>& data,
				   const std::array<unsigned char, 32>& key,
				   const std::array<unsigned char, 16>& iv) {
	EVP_CIPHER_CTX* evp_context = EVP_CIPHER_CTX_new();
	if (!evp_context)
		cli::fatal("htool: openssl evp context creation failed");

	// Attempt to initialize encryption.
	if (!EVP_EncryptInit_ex(
		evp_context, 
		EVP_aes_256_cbc(), 
		nullptr, 
		key.data(), 
		iv.data())
	) {
		EVP_CIPHER_CTX_free(evp_context);
		cli::fatal("htool: openssl evp encryption init failed");
	}

	// Initialize ciphertext buffer to read into.
	int len = 0;
	int encrypted_len = 0;
	std::vector<unsigned char> encrypted_data(
		data.size() + EVP_MAX_BLOCK_LENGTH);

	// Attempt to encrypt data.
	if (!EVP_EncryptUpdate(evp_context, encrypted_data.data(), &len, 
		data.data(), data.size())) {
		EVP_CIPHER_CTX_free(evp_context);
		cli::fatal("htool: openssl evp encryption update failed");
	}

	encrypted_len = len;

	// Attempt to finalize encryption.
	if (!EVP_EncryptFinal_ex(evp_context, encrypted_data.data() + len, &len)) {
		EVP_CIPHER_CTX_free(evp_context);
		cli::fatal("htool: openssl evp encryption finalization failed");
	}

	// Resize ciphertext buffer to actual read size.
	encrypted_data.resize(encrypted_len + len);
	EVP_CIPHER_CTX_free(evp_context);
	return encrypted_data;
}

std::vector<unsigned char> 
htool::aes_decrypt(const std::vector<unsigned char>& data,
                   const std::array<unsigned char, 32>& key,
                   const std::array<unsigned char, 16>& iv) {
	EVP_CIPHER_CTX* evp_context = EVP_CIPHER_CTX_new();
	if (!evp_context)
		cli::fatal("htool: openssl evp context creation failed");

	if (!EVP_DecryptInit_ex(
		evp_context, 
		EVP_aes_256_cbc(), 
		nullptr, 
		key.data(), 
		iv.data())
	) {
		EVP_CIPHER_CTX_free(evp_context);
		cli::fatal("htool: openssl evp decryption init failed");
	}

	/// Initialize plaintext buffer to read into.
	int len = 0;
	int decrypted_len = 0;
	std::vector<unsigned char> decrypted_data(
		data.size() + EVP_MAX_BLOCK_LENGTH);

	// Attempt to decrypt data.
	if (!EVP_DecryptUpdate(evp_context, decrypted_data.data(), &len, 
		data.data(), data.size())) {
		EVP_CIPHER_CTX_free(evp_context);
		cli::fatal("htool: openssl evp decryption update failed");
	}

	decrypted_len = len;

	// Attempt to finalize decryption.
	if (!EVP_DecryptFinal_ex(evp_context, decrypted_data.data() + len, &len)) {
		uint64_t err = ERR_get_error();
		EVP_CIPHER_CTX_free(evp_context);
		cli::fatal("htool: openssl evp decryption finalization failed");
	}

	// Resize plaintext buffer to actual read size.
	decrypted_data.resize(decrypted_len + len);
	EVP_CIPHER_CTX_free(evp_context);
	return decrypted_data;
}

std::vector<unsigned char> 
htool::hash_password(const std::string& data, 
					 const std::vector<unsigned char>& salt,
                	 const uint32_t iterations, const uint32_t len) {
  	std::vector<unsigned char> hash(len);
  	if (!PKCS5_PBKDF2_HMAC(
		data.c_str(), 
		data.size(), 
		salt.data(), 
		salt.size(),
      	iterations, 
		EVP_sha256(), 
		len, 
		hash.data())
	) {
    	cli::fatal("htool: failed to hash password");
  	}

  	return hash;
}

bool htool::match_password(const std::string& pw,
                           const std::vector<unsigned char>& hash,
                           const std::vector<unsigned char>& salt) {
	std::vector<unsigned char> hashed = hash_password(pw, salt);
	return std::string(hash.begin(), hash.end()) == std::string(
		hashed.begin(), hashed.end());
}

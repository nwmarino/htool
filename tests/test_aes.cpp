#define CATCH_CONFIG_MAIN

#include "../include/encryption.h"

#include "catch2/catch_test_macros.hpp"

#include <vector>

using namespace htool;

TEST_CASE("Basic Encryption", "[aes]") {
    std::array<unsigned char, 32> key = generate_key();
    std::array<unsigned char, 16> iv = generate_iv();
    std::vector<unsigned char> input_data = {'T', 'e', 's', 't'};
    std::vector<unsigned char> encrypted_data;
    std::vector<unsigned char> decrypted_data;

    // Run encryption and ensure it did something.
    encrypted_data = aes_encrypt(input_data, key, iv);
    REQUIRE(encrypted_data != input_data);

    // Run decryption and ensure the decrypted data matches the input data.
    decrypted_data = aes_decrypt(encrypted_data, key, iv);
    REQUIRE(decrypted_data == input_data);
}

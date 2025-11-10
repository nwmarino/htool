#include "../include/encryption.h"

#include "catch2/catch_test_macros.hpp"
#include "catch2/generators/catch_generators.hpp"

#include <vector>

using namespace htool;

TEST_CASE("Random Byte Generation", "[rand]") {
    int random = GENERATE(1, 256);
    std::vector<unsigned char> rand_data = generate_rand(random);

    REQUIRE(rand_data.size() == random);
}

TEST_CASE("Empty Bytes", "[rand]") {
    std::vector<unsigned char> empty_data = generate_rand(0);

    REQUIRE(empty_data.size() == 0);
    REQUIRE(empty_data.empty());
}

TEST_CASE("IV Generation", "[rand]") {
    std::array<unsigned char, 16> iv = generate_iv();

    REQUIRE(iv.size() == 16);
    REQUIRE(!iv.empty());
}

TEST_CASE("Key Generation", "[rand]") {
    std::array<unsigned char, 32> key = generate_key();
	
    REQUIRE(key.size() == 32);
    REQUIRE(!key.empty());
}

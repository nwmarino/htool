#include "../include/encryption.h"

#include "catch2/catch_test_macros.hpp"

#include <fstream>
#include <vector>

using namespace htool;

TEST_CASE("Checksum Computation", "[hash]") {
    std::ofstream file1("test1.txt");
    file1 << "Test";
    file1.close();
    std::array<unsigned char, 32> checksum1 = compute_checksum("test1.txt");
    std::remove("test1.txt");
    REQUIRE(checksum1.size() == 32);

    std::ofstream file2("test2.txt");
    file2 << "Test";
    file2.close();
    std::array<unsigned char, 32> checksum2 = compute_checksum("test2.txt");
    std::remove("test2.txt");
    REQUIRE(checksum2.size() == 32);

    REQUIRE(checksum1 == checksum2);
}

TEST_CASE("Password Hashing", "[hash]") {
    std::string password = "password";
    std::vector<unsigned char> salt = generate_rand(16);
    std::vector<unsigned char> hash = hash_password(password, salt);
    REQUIRE(hash.size() == 32);
    REQUIRE(match_password(password, hash, salt));
}

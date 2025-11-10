#include "../include/container.h"

#include "boost/filesystem/operations.hpp"
#include "catch2/catch_test_macros.hpp"

namespace fs = boost::filesystem;

using namespace htool;

TEST_CASE("Container Creation", "[container]") {
	Container* container_c = Container::create("test", "password");
	delete container_c;

	REQUIRE(fs::exists("test"));
	REQUIRE(fs::file_size("test") == 32768);
	fs::remove("test");
}

TEST_CASE("Container Opening", "[container]") {
	Container* container_c = Container::create("test", "password");
	delete container_c;
	REQUIRE(fs::exists("test"));

	Container* container_o = Container::open("test", "password");
	delete container_o;

	REQUIRE(fs::exists("test"));
	fs::remove("test");
}

TEST_CASE("Container Empty FAT persistence", "[container]") {
	Container* container_c = Container::create("test", "password");
	const std::vector<FATEntry> fat_c = container_c->get_fat();
	delete container_c;

	Container* container_o = Container::open("test", "password");
	container_o->load_fat();
	const std::vector<FATEntry> fat_o = container_o->get_fat();
	delete container_o;
	
	REQUIRE(fat_c.empty());
	REQUIRE(fat_o.empty());
	REQUIRE(fat_c.size() == fat_o.size());

	for (const FATEntry& entry : fat_c) {
		auto it = std::find_if(
			fat_o.begin(),
			fat_o.end(),
			[&entry](const FATEntry &e) -> bool {
				return e.filename == entry.filename;
			});

		REQUIRE(it != fat_o.end());
	}

	REQUIRE(fs::exists("test"));
	fs::remove("test");
}

TEST_CASE("Container file storing", "[container]") {
	Container* container = Container::create("test", "password");

	std::ofstream file("test_file");
	REQUIRE(fs::exists("test_file"));
	file << "test";
	file.close();
	container->store_file("test_file");

	delete container;
	fs::remove("test_file");

	// One block size since the file is 4 bytes, 12 byte padding.
	REQUIRE(fs::file_size("test") == 32768 + 16);
  	fs::remove("test");
}

TEST_CASE("Container file loading", "[container]") {
	Container* container_c = Container::create("test", "password");
	delete container_c;

	Container* container_o = Container::open("test", "password");

	std::ofstream input_file("test_file");
	REQUIRE(fs::exists("test_file"));
	input_file << "test";
	input_file.close();

	container_o->store_file("test_file");
	fs::remove("test_file");
	container_o->load_file("test_file");

	// Check that test_file contains "test".
	REQUIRE(fs::exists("test_file"));
	std::ifstream out_file("test_file");
	std::string content;
	out_file >> content;
	out_file.close();

	REQUIRE(content == "test");
	delete container_o;
	fs::remove("test_file");
	fs::remove("test");
}

TEST_CASE("Container file deletion", "[container]") {
	Container* container_c = Container::create("test", "password");
	delete container_c;

	Container* container_o = Container::open("test", "password");

	std::ofstream input_file("test_file");
	REQUIRE(fs::exists("test_file"));
	input_file << "test";
	input_file.close();

	REQUIRE_NOTHROW(container_o->store_file("test_file"));
	fs::remove("test_file");
	REQUIRE(!container_o->get_fat().empty());

	REQUIRE(container_o->delete_file("test_file"));

	REQUIRE(!fs::exists("test_file"));
	REQUIRE(container_o->get_fat().empty());

	delete container_o;
	fs::remove("test");
}

TEST_CASE("Empty Container File Deletion", "[container]") {
	Container* container = Container::create("test", "password");
	REQUIRE(container->get_fat().empty());

	REQUIRE(!container->delete_file("test_file"));
	REQUIRE(container->get_fat().empty());

	delete container;
	fs::remove("test");
}

TEST_CASE("Large Container File Deletion", "[container]") {
	Container* container = Container::create("test", "password");
	REQUIRE(container->get_fat().empty());

	std::ofstream input_file1("test_file1");
	REQUIRE(fs::exists("test_file1"));
	input_file1 << "test1";
	input_file1.close();

	std::ofstream input_file2("test_file2");
	REQUIRE(fs::exists("test_file2"));
	input_file2 << "test1";
	input_file2.close();

	container->store_file("test_file1");
	container->store_file("test_file2");
	fs::remove("test_file1");
	fs::remove("test_file2");
	REQUIRE(!container->get_fat().empty());

	REQUIRE(container->delete_file("test_file2"));
	REQUIRE(!container->get_fat().empty());

	delete container;
	fs::remove("test");
}

TEST_CASE("Container Compaction", "[container]") {
	Container* container = Container::create("test", "password");
	REQUIRE(fs::exists("test"));
	
	// Create two test files.
	std::ofstream input_file1("test_file1");
	REQUIRE(fs::exists("test_file1"));
	input_file1 << "test1";
	input_file1.close();
	std::ofstream input_file2("test_file2");
	REQUIRE(fs::exists("test_file2"));
	input_file2 << "test2";
	input_file2.close();

	// Store the test files to the container, and remove them from the local tree.
	container->store_file("test_file1");
	container->store_file("test_file2");
	fs::remove("test_file1");
	fs::remove("test_file2");
	delete container;

	// Check that the container is the correct size. 32768 + 2 * (5 + 11 (padding)).
	REQUIRE(fs::file_size("test") == 32768 + (16 * 2));

	Container* container_o = Container::open("test", "password");

	// Delete the first file from the container.
	REQUIRE(container_o->delete_file("test_file1"));

	// Check that the container size has not changed.
	REQUIRE(fs::file_size("test") == 32768 + (16 * 2));
	REQUIRE(!container_o->get_fat().empty());

	// Compact the container.
	container_o->compact();
	REQUIRE(!container_o->get_fat().empty());
	delete container_o;

	// Check that the container is the correct size. 32768 + 5 + 11 (padding).
	REQUIRE(fs::file_size("test") == 32768 + 16);
	fs::remove("test");
}

/// Check that compacting an empty container does not compact the reserved space.
TEST_CASE("Empty Container Compaction", "[container]") {
    Container* container = Container::create("test", "password");
    REQUIRE(fs::exists("test"));
    REQUIRE(container->get_fat().empty());

    container->compact();
    delete container;
    REQUIRE(fs::file_size("test") == 32768);
    fs::remove("test");
}

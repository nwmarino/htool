cmake_minimum_required(VERSION 3.20.0)
set(CMAKE_CXX_STANDARD 20)
project(htool VERSION 1.0)

cmake_policy(SET CMP0167 NEW)
find_package(Boost REQUIRED COMPONENTS filesystem program_options iostreams)
find_package(OpenSSL REQUIRED)

include(FetchContent)

FetchContent_Declare(
    catch2
    GIT_REPOSITORY https://github.com/catchorg/Catch2.git
    GIT_TAG v3.4.0
)

FetchContent_MakeAvailable(catch2)

set(INCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/include)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})

add_executable(htool
    src/cli.cpp
    src/container.cpp
    src/encryption.cpp
    src/fat.cpp
    src/file.cpp
    src/htool.cpp
)

include_directories(${Boost_INCLUDE_DIRS})
include_directories(${INCLUDE_DIR})

target_link_libraries(htool
    PRIVATE
        ${Boost_LIBRARIES}
        OpenSSL::Crypto
        OpenSSL::SSL
)

target_include_directories(htool
    PUBLIC
        ${PROJECT_BINARY_DIR}
        ${INCLUDE_DIR}
)

# 
# Testing
#

file(GLOB TEST_SOURCES tests/*.cpp)
add_executable(htool_tests ${TEST_SOURCES} 
    src/cli.cpp
    src/container.cpp
    src/encryption.cpp
    src/fat.cpp
    src/file.cpp
)

target_link_libraries(htool_tests
    PRIVATE
        ${Boost_LIBRARIES}
        Catch2::Catch2WithMain
        OpenSSL::Crypto
)

include(CTest)
include(Catch)
catch_discover_tests(htool_tests)

cmake_minimum_required(VERSION 4.1)
project(HashCracker)

set(CMAKE_CXX_STANDARD 20)

add_executable(HashCracker HashCracker.cpp)

find_package(OpenSSL REQUIRED)

target_link_libraries(HashCracker OpenSSL::SSL OpenSSL::Crypto)


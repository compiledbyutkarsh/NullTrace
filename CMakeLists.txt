cmake_minimum_required(VERSION 3.16)
project(NullTrace VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -O2")

include_directories(include)

file(GLOB_RECURSE SOURCES
    src/*.cpp
    src/protocols/*.cpp
    src/capture/*.cpp
    src/analysis/*.cpp
    src/ui/*.cpp
)

add_executable(nulltrace ${SOURCES})

target_link_libraries(nulltrace pcap pthread)

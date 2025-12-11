# CMakeList.txt : CMake project for ping, include source and define
# project specific logic here.
#
cmake_minimum_required(VERSION 3.16)

project ("ping" VERSION 0.1.0)

# C++17 required
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Add source to this project's executable.
add_executable (ping "ping.cpp")

# Need link dl for Linux
if (UNIX AND NOT APPLE)
    target_link_libraries(ping PRIVATE dl)
endif()

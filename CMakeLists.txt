cmake_minimum_required(VERSION 3.23)
project(vm_translator)

set(CMAKE_CXX_STANDARD 20)

include_directories(.)
include_directories(src)

add_executable(vm_translator
        src/Rex.cpp
        src/Rex.h
        main.cpp)

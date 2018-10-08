cmake_minimum_required(VERSION 3.2 FATAL_ERROR)
project(logfault VERSION 0.1 LANGUAGES CXX)

message(STATUS "Using ${CMAKE_CXX_COMPILER}")

macro(SET_CPP_STANDARD target)
    message(STATUS "Using C++ 11 for ${target}")
    set_property(TARGET ${target} PROPERTY CXX_STANDARD 11)
endmacro(SET_CPP_STANDARD)

find_package (Threads)
set(DEFAULT_LIBRARIES  ${CMAKE_THREAD_LIBS_INIT})
include_directories(
    ${CMAKE_SOURCE_DIR}/include
    )

add_subdirectory(tests)


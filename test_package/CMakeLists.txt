cmake_minimum_required(VERSION 3.14 FATAL_ERROR)
project (example)

find_package (Threads)
find_package (Logfault REQUIRED)

add_executable(${PROJECT_NAME} main.cpp)
target_link_libraries(${PROJECT_NAME} PRIVATE
    logfault::logfault
    Threads::Threads
)


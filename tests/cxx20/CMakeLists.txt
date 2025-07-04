# tests/cxx20/CMakeLists.txt
cmake_minimum_required(VERSION 3.5)
project(logfault_cxx20_tests CXX)

# Require C++20
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_executable(${PROJECT_NAME}
    ${PROJECT_NAME}.cpp
)

target_include_directories(${PROJECT_NAME}
    PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${LOGFAULT_ROOT}/include
    ${GTEST_INCLUDE_DIRS}
    ${CMAKE_BINARY_DIR}/exports
    )

target_link_libraries(${PROJECT_NAME}
    ${GTEST_LIBRARIES}
    ${CMAKE_THREAD_LIBS_INIT}
)

# register with CTest
add_test(NAME ${PROJECT_NAME}
         COMMAND ${PROJECT_NAME})

cmake_minimum_required(VERSION 3.5 FATAL_ERROR)

set (LOGFAULT_VERSION 0.6.3)

if(CMAKE_VERSION VERSION_LESS "3.12")
    project(logfault VERSION ${LOGFAULT_VERSION} LANGUAGES CXX)
else()
    project(logfault
        DESCRIPTION "Simple to use, header only C++ library for application-logging on all major platforms."
        HOMEPAGE_URL https://github.com/jgaa/logfault
        VERSION ${LOGFAULT_VERSION}
        LANGUAGES CXX)
endif()

include(GNUInstallDirs)

set(LOGFAULT_ROOT ${CMAKE_CURRENT_SOURCE_DIR})

message(STATUS "Using ${CMAKE_CXX_COMPILER}")

find_package (Threads)
set(DEFAULT_LIBRARIES  ${CMAKE_THREAD_LIBS_INIT})
include_directories(${PROJECT_SOURCE_DIR}/include)

option(LOGFAULT_BUILD_TESTS "Build tests" OFF)

if(LOGFAULT_BUILD_TESTS)
    find_package(GTest REQUIRED)
    include(CTest)
    enable_testing()
    add_subdirectory(tests)
endif()

add_library(${PROJECT_NAME} INTERFACE)

target_include_directories(
  ${PROJECT_NAME}
  INTERFACE $<BUILD_INTERFACE:${${PROJECT_NAME}_SOURCE_DIR}/include>
            $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>)

install(TARGETS ${PROJECT_NAME}
        EXPORT ${PROJECT_NAME}_Targets
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})

install(DIRECTORY ${PROJECT_SOURCE_DIR}/include/logfault DESTINATION include)

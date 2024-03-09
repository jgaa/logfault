cmake_minimum_required(VERSION 3.2 FATAL_ERROR)

project(logfault
    DESCRIPTION "Simple to use, header only C++ library for application-logging on all major platforms."
    HOMEPAGE_URL https://github.com/jgaa/logfault
    VERSION 0.5.0
    LANGUAGES CXX)

include(GNUInstallDirs)

set(LOGFAULT_ROOT ${CMAKE_CURRENT_SOURCE_DIR})

find_package (Threads)
set(DEFAULT_LIBRARIES  ${CMAKE_THREAD_LIBS_INIT})
include_directories(
    ${PROJECT_SOURCE_DIR}/include
    )

option(LOGFAULT_BUILD_TESTS "Build tests" ON)

if(LOGFAULT_BUILD_TESTS)
    find_package(GTest REQUIRED)
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

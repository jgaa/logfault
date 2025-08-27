cmake_minimum_required(VERSION 3.05...3.30 FATAL_ERROR)

set (LOGFAULT_VERSION 0.7.1)

project(logfault
    DESCRIPTION "Simple to use, header only C++ library for application-logging on all major platforms."
    HOMEPAGE_URL https://github.com/jgaa/logfault
    VERSION ${LOGFAULT_VERSION}
    LANGUAGES CXX)

include(GNUInstallDirs)

set(LOGFAULT_ROOT ${CMAKE_CURRENT_SOURCE_DIR})

message(STATUS "Using ${CMAKE_CXX_COMPILER}")

find_package (Threads)
set(DEFAULT_LIBRARIES  ${CMAKE_THREAD_LIBS_INIT})

add_library(${PROJECT_NAME} INTERFACE)

# === Apple os_log support ===
option(LOGFAULT_USE_OS_LOG "Enable os_log support on Apple platforms" ON)

if(APPLE AND LOGFAULT_USE_OS_LOG)
  # os_log lives in the 'os' framework on Apple platforms
  # Use find_library so we get a proper framework reference with Xcode/Clang.
  find_library(LOGFAULT_OS_FRAMEWORK os)

  if(LOGFAULT_OS_FRAMEWORK)
    target_link_libraries(${PROJECT_NAME} INTERFACE "${LOGFAULT_OS_FRAMEWORK}")
    add_compile_definitions(-DLOGFAULT_HAVE_OS_LOG=1)
    message(STATUS "logfault: os_log enabled (linking with framework: ${LOGFAULT_OS_FRAMEWORK})")
  else()
    message(WARNING "logfault: Apple 'os' framework not found; os_log support disabled")
  endif()
endif()

option(LOGFAULT_BUILD_TESTS "Build tests" OFF)

if (CMAKE_SYSTEM_NAME STREQUAL "Linux")
    option(LOGFAULT_BUILD_PERF "Build Performance Benchmarks" OFF)
endif()

if(LOGFAULT_BUILD_TESTS)
    find_package(GTest REQUIRED)
    include(CTest)
    enable_testing()
    add_subdirectory(tests)
endif()

if (LOGFAULT_BUILD_PERF)
    add_subdirectory(perf)
endif()

target_include_directories(${PROJECT_NAME}
  INTERFACE
    $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
)

## Provide a nice alias (so consumers always write logfault::logfault)
add_library(logfault::logfault ALIAS ${PROJECT_NAME})

#
# Installation
#
# 1) Header files
install(
  DIRECTORY "${PROJECT_SOURCE_DIR}/include/logfault"
  DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}"
  FILES_MATCHING PATTERN "*.hpp" PATTERN "*.h"
)

# 2) Interface library “logfault” (and its alias “logfault::logfault”)
install(
  TARGETS logfault       # the INTERFACE target
  EXPORT ${PROJECT_NAME}_Targets
  INCLUDES DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}"
)

# 3) Config files for find_package(... CONFIG)
include(CMakePackageConfigHelpers)
configure_package_config_file(
  "${CMAKE_CURRENT_LIST_DIR}/cmake/LogfaultConfig.cmake.in"
  "${CMAKE_CURRENT_BINARY_DIR}/logfaultConfig.cmake"
  INSTALL_DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/logfault"
)
write_basic_package_version_file(
  "${CMAKE_CURRENT_BINARY_DIR}/logfaultConfigVersion.cmake"
  VERSION ${PROJECT_VERSION}
  COMPATIBILITY AnyNewerVersion
)

install(
  EXPORT ${PROJECT_NAME}_Targets
  NAMESPACE logfault::
  FILE     "${PROJECT_NAME}Targets.cmake"
  DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/logfault"
)

install(
  FILES
    "${CMAKE_CURRENT_BINARY_DIR}/logfaultConfig.cmake"
    "${CMAKE_CURRENT_BINARY_DIR}/logfaultConfigVersion.cmake"
  DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/logfault"
)

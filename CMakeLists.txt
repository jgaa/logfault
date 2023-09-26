cmake_minimum_required(VERSION 3.2 FATAL_ERROR)
project(logfault VERSION 0.2 LANGUAGES CXX)
include(GNUInstallDirs)

message(STATUS "Using ${CMAKE_CXX_COMPILER}")

macro(SET_CPP_STANDARD target)
    message(STATUS "Using C++ 11 for ${target}")
    set_property(TARGET ${target} PROPERTY CXX_STANDARD 11)
endmacro(SET_CPP_STANDARD)

find_package (Threads)
set(DEFAULT_LIBRARIES  ${CMAKE_THREAD_LIBS_INIT})
include_directories(
    ${PROJECT_SOURCE_DIR}/include
    )

option(LOGFAULT_BUILD_TESTS "Build tests" ON)

if(LOGFAULT_BUILD_TESTS)
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

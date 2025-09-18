
if(TARGET GTest::gtest)
    set(GTEST_LIBRARIES GTest::gtest)
elseif(TARGET gtest::gtest)
    set(GTEST_LIBRARIES gtest::gtest)
else()
    message(FATAL_ERROR "Neither GTest::gtest nor gtest::gtest targets were found")
endif()

# near the top of this CMake (before targets)
find_package(Boost 1.75 REQUIRED COMPONENTS json)

add_subdirectory(cxx11)
add_subdirectory(cxx14)
add_subdirectory(cxx17)
add_subdirectory(cxx20)
add_subdirectory(cxx23)

####### default_to_clog

add_executable(default_to_clog
    default_to_clog.cpp
    )

set_property(TARGET default_to_clog PROPERTY CXX_STANDARD 14)

target_include_directories(default_to_clog
    PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${LOGFAULT_ROOT}/include
    ${GTEST_INCLUDE_DIRS}
    ${CMAKE_BINARY_DIR}/exports
    )

target_link_libraries(default_to_clog
    logfault::logfault
    ${GTEST_LIBRARIES}
    ${CMAKE_THREAD_LIBS_INIT}
)

add_test(NAME default_to_clog COMMAND default_to_clog)

####### default_to_clog_with_tid

add_executable(default_to_clog_with_tid
    default_to_clog.cpp
    )

target_compile_definitions(default_to_clog_with_tid PRIVATE LOGFAULT_USE_TID_AS_NAME=1)

set_property(TARGET default_to_clog_with_tid PROPERTY CXX_STANDARD 14)

target_include_directories(default_to_clog_with_tid
    PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${LOGFAULT_ROOT}/include
    ${GTEST_INCLUDE_DIRS}
    ${CMAKE_BINARY_DIR}/exports
    )

target_link_libraries(default_to_clog_with_tid
    logfault::logfault
    ${GTEST_LIBRARIES}
    ${CMAKE_THREAD_LIBS_INIT}
)

add_test(NAME default_to_clog_with_tid COMMAND default_to_clog_with_tid)


###### json_tests

add_executable(json_tests
    json_tests.cpp
    )

target_compile_definitions(json_tests PRIVATE LOGFAULT_USE_TID_AS_NAME=1)

set_property(TARGET json_tests PROPERTY CXX_STANDARD 17)

target_include_directories(json_tests
    PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${LOGFAULT_ROOT}/include
    ${GTEST_INCLUDE_DIRS}
    ${CMAKE_BINARY_DIR}/exports
    )

target_link_libraries(json_tests
    logfault::logfault
    ${GTEST_LIBRARIES}
    Boost::json
    ${CMAKE_THREAD_LIBS_INIT}
)

add_test(NAME json_tests COMMAND json_tests)


####### json_escape_tests

add_executable(json_escape_tests
    json_escape_tests.cpp
    )

target_compile_definitions(json_escape_tests PRIVATE LOGFAULT_USE_TID_AS_NAME=1)

set_property(TARGET json_escape_tests PROPERTY CXX_STANDARD 17)

target_include_directories(json_escape_tests
    PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${LOGFAULT_ROOT}/include
    ${GTEST_INCLUDE_DIRS}
    ${CMAKE_BINARY_DIR}/exports
    )

target_link_libraries(json_escape_tests
    logfault::logfault
    ${GTEST_LIBRARIES}
    ${CMAKE_THREAD_LIBS_INIT}
)

add_test(NAME json_escape_tests COMMAND json_escape_tests)


if (CMAKE_SYSTEM_NAME STREQUAL "Linux")
    ####### systemd_tests


    add_executable(systemd_tests
        systemd_tests.cpp
        )

    target_compile_definitions(systemd_tests PRIVATE LOGFAULT_USE_TID_AS_NAME=1)

    set_property(TARGET systemd_tests PROPERTY CXX_STANDARD 17)

    target_include_directories(systemd_tests
        PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${LOGFAULT_ROOT}/include
        ${GTEST_INCLUDE_DIRS}
        ${CMAKE_BINARY_DIR}/exports
        )

    target_link_libraries(systemd_tests
        logfault::logfault
        ${GTEST_LIBRARIES}
        ${CMAKE_THREAD_LIBS_INIT}
    )

    add_test(NAME systemd_tests COMMAND systemd_tests)

endif()

if (CMAKE_SYSTEM_NAME STREQUAL "Darwin")
    ####### os_log_tests


    add_executable(os_log_tests
        os_log_tests.cpp
        )

    target_compile_definitions(os_log_tests PRIVATE LOGFAULT_USE_TID_AS_NAME=1)

    set_property(TARGET os_log_tests PROPERTY CXX_STANDARD 17)

    target_include_directories(os_log_tests
        PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${LOGFAULT_ROOT}/include
        ${GTEST_INCLUDE_DIRS}
        ${CMAKE_BINARY_DIR}/exports
        )

    target_link_libraries(os_log_tests
        logfault::logfault
        ${GTEST_LIBRARIES}
        ${CMAKE_THREAD_LIBS_INIT}
    )

    add_test(NAME os_log_tests COMMAND os_log_tests)

endif()

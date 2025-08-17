
if(TARGET GTest::gtest)
    set(GTEST_LIBRARIES GTest::gtest)
elseif(TARGET gtest::gtest)
    set(GTEST_LIBRARIES gtest::gtest)
else()
    message(FATAL_ERROR "Neither GTest::gtest nor gtest::gtest targets were found")
endif()

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



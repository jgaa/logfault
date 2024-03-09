

option(WITH_QT "Enable QT" OFF)

# if (WITH_QT)
#     add_definitions(-DLOGFAULT_USE_QT_LOG=1)
#     find_package(Qt6 6.4 REQUIRED COMPONENTS Test)
#     qt_standard_project_setup(REQUIRES 6.5)
#     qt_add_executable(general_tests general_tests.cpp)

# else()
#     add_executable(general_tests general_tests.cpp)
#     target_link_libraries(general_tests
#         ${DEFAULT_LIBRARIES}
#     )
# endif()

####### default_to_clog

add_executable(default_to_clog
    default_to_clog.cpp
    )

set_property(TARGET default_to_clog PROPERTY CXX_STANDARD 11)

target_include_directories(default_to_clog
    PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${LOGFAULT_ROOT}/include
    ${GTEST_INCLUDE_DIRS}
    )

target_link_libraries(default_to_clog
    ${GTEST_LIBRARIES}
    ${CMAKE_THREAD_LIBS_INIT}
)

add_test(NAME default_to_clog COMMAND default_to_clog)

####### default_to_clog_with_tid

add_executable(default_to_clog_with_tid
    default_to_clog.cpp
    )

target_compile_definitions(default_to_clog_with_tid PRIVATE LOGFAULT_USE_TID_AS_NAME=1)

set_property(TARGET default_to_clog_with_tid PROPERTY CXX_STANDARD 11)

target_include_directories(default_to_clog_with_tid
    PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${LOGFAULT_ROOT}/include
    ${GTEST_INCLUDE_DIRS}
    )

target_link_libraries(default_to_clog_with_tid
    ${GTEST_LIBRARIES}
    ${CMAKE_THREAD_LIBS_INIT}
)

add_test(NAME default_to_clog_with_tid COMMAND default_to_clog_with_tid)

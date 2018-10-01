
enable_testing()

macro (ADD_AND_RUN_UNITTEST testname targetname)
SET_CPP_STANDARD(${targetname})
add_test(NAME ${testname} COMMAND ${targetname})
if (AUTORUN_UNIT_TESTS)
    add_custom_command(
        TARGET ${targetname}
        POST_BUILD
        COMMENT "running ${testname}"
        WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
        COMMAND ${CMAKE_CTEST_COMMAND} -C $<CONFIGURATION> -R "${testname}"  --output-on-failure
    )
endif()
endmacro()


add_executable(general_tests general_tests.cpp)
target_link_libraries(general_tests
    ${DEFAULT_LIBRARIES}
)
ADD_AND_RUN_UNITTEST(GENERAL_TESTS general_tests)


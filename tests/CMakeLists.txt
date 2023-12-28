

option(WITH_QT "Enable QT" OFF)

if (WITH_QT)
    add_definitions(-DLOGFAULT_USE_QT_LOG=1)
    find_package(Qt6 6.4 REQUIRED COMPONENTS Test)
    qt_standard_project_setup(REQUIRES 6.5)
    qt_add_executable(general_tests general_tests.cpp)

else()
    add_executable(general_tests general_tests.cpp)
    target_link_libraries(general_tests
        ${DEFAULT_LIBRARIES}
    )
endif()



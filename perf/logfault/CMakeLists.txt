project (LogfaultPerf)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# We need boost program_options for command line parsing
find_package(Boost 1.80 REQUIRED COMPONENTS
    program_options
    log
)

find_package(spdlog REQUIRED)

add_executable(${PROJECT_NAME}
    main.cpp
)

target_link_libraries(
    ${PROJECT_NAME}
    PRIVATE
        logfault::logfault
        Threads::Threads
        Boost::program_options
        Boost::log
        spdlog::spdlog
)

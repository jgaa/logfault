#define LOGFAULT_WITH_OS_LOG
#include "logfault/logfault.h"
#include "gtest/gtest.h"

using namespace std;
using namespace logfault;

namespace {
std::vector<std::string> sink;
}


TEST(OsLogHandler, DoActualLoggingWithSystemd) {
    using namespace logfault;

    logfault::LogManager::Instance().AddHandler(
        std::make_unique<logfault::OsLogHandler>(
            "oslog",
            logfault::LogLevel::DEBUGGING,
            logfault::OsLogHandler::Options{"com.example.app", "network"}
            )
        );

    LFLOG_INFO << "Hello from os_log test";

    logfault::LogManager::Instance().RemoveHandler("oslog");
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}

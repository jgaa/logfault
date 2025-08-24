#define LOGFAULT_WITH_SYSTEMD
#include "logfault/logfault.h"
#include "gtest/gtest.h"

using namespace std;
using namespace logfault;

namespace {
    std::vector<std::string> sink;
}

TEST(SystemdHandler, SendsExpectedFields) {
    using namespace logfault;

    auto fake_sendv = +[](const struct iovec* iov, int n) -> int {
        // Capture via a static so we can read it after the call,
        // or use a global test fixture to hold the sink.
        sink.clear();
        for (int i = 0; i < n; ++i) {
            sink.emplace_back(std::string((char*)iov[i].iov_base, iov[i].iov_len));
        }
        return 0;
    };

    SystemdHandler::Options opt;
    opt.ident = "logfault-test";

    auto handler = make_unique<SystemdHandler> (fake_sendv, "systemd", LogLevel::INFO, opt);

    Message msg{"hello", LogLevel::INFO, "main.cpp", 42};
    handler->LogMessage(msg);

    // Assertions: keys present, values correct
    auto has = [&](std::string_view kv) {
        auto& s = sink;
        return std::find(sink.begin(), sink.end(), kv) != sink.end();
    };

    EXPECT_TRUE(has("MESSAGE=hello"));
    EXPECT_TRUE(has("PRIORITY=6"));        // INFO -> 6
    EXPECT_TRUE(has("CODE_FILE=main.cpp"));
    EXPECT_TRUE(has("CODE_LINE=42"));
    EXPECT_TRUE(has("SYSLOG_IDENTIFIER=logfault-test"));
}

TEST(SystemdHandler, DoActualLoggingWithSystemd) {
    using namespace logfault;

    logfault::LogManager::Instance().AddHandler(
        make_unique<SystemdHandler>("systemd"));

    LFLOG_INFO << "Hello from systemd test";

    logfault::LogManager::Instance().RemoveHandler("systemd");
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}

#include <regex>

#include "logfault/logfault.h"
#include "gtest/gtest.h"

using namespace std;
using namespace logfault;

namespace {
struct ClogRedirector {
    ClogRedirector(string& out, ostream& ios = std::clog)
        : out_{out}, ios_{ios} {

        orig_ = ios.rdbuf();
        ios_.rdbuf(buffer_.rdbuf());
    }

    ~ClogRedirector() {
        out_ = buffer_.str();
        ios_.rdbuf(orig_);
    }

private:
    ostream& ios_;
    decltype(std::clog.rdbuf()) orig_{};
    stringstream buffer_;
    string& out_;
};
} // namespace

TEST(Logfault, HelloTrace) {

    string output;
    {
        ClogRedirector redir{output};
        LFLOG_TRACE << "Test log";
    }

    regex pattern{R"(.* TRACE .* Test log.*)"};
    EXPECT_TRUE(regex_search(output, pattern));
}

TEST(Logfault, HelloDebug) {

    string output;
    {
        ClogRedirector redir{output};
        LFLOG_DEBUG << "Test log";
    }

    regex pattern{R"(.* DEBUGGING .* Test log.*)"};
    EXPECT_TRUE(regex_search(output, pattern));
}

TEST(Logfault, HelloInfo) {

    string output;
    {
        ClogRedirector redir{output};
        LFLOG_INFO << "Test log";
    }

    regex pattern{R"(.* INFO .* Test log.*)"};
    EXPECT_TRUE(regex_search(output, pattern));
}

TEST(Logfault, HelloWarn) {

    string output;
    {
        ClogRedirector redir{output};
        LFLOG_WARN << "Test log";
    }

    regex pattern{R"(.* WARNING .* Test log.*)"};
    EXPECT_TRUE(regex_search(output, pattern));
}

TEST(Logfault, HelloError) {

    string output;
    {
        ClogRedirector redir{output};
        LFLOG_ERROR << "Test log";
    }

    regex pattern{R"(.* ERROR .* Test log.*)"};
    EXPECT_TRUE(regex_search(output, pattern));
}

#if defined(__linux__) && defined(LOGFAULT_USE_TID_AS_NAME)
TEST(Logfault, HelloTid) {

    string output;
    {
        ClogRedirector redir{output};
        LFLOG_INFO << "Test log";
    }

    regex pattern{R"(.* INFO [0-9]{1,8} Test log.*)"};
    EXPECT_TRUE(regex_search(output, pattern));
}
#endif

#if defined(WIN32) && defined(LOGFAULT_USE_TID_AS_NAME)
TEST(Logfault, HelloTid) {

    string output;
    {
        ClogRedirector redir{ output };
        LFLOG_INFO << "Test log";
    }

    regex pattern{ R"(.* INFO [0-9]{1,10} Test log.*)" };
    EXPECT_TRUE(regex_search(output, pattern));
    cout << "Output: " << output << endl;
}
#endif


int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);

    logfault::LogManager::Instance().AddHandler(
        make_unique<logfault::StreamHandler>(clog, logfault::LogLevel::TRACE));
    return RUN_ALL_TESTS();
}

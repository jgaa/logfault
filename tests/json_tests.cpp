#include <gtest/gtest.h>
#include <sstream>
#include <string>
#include <memory>

#include <boost/json.hpp>

// pull in the JsonEscape template from your library
#define LOGFAULT_ENABLE_LOCATION 1
#include "logfault/logfault.h"

using namespace std;
using namespace logfault;
using namespace std::string_literals;


namespace {
// Helper to run the escape and return the result
std::string escape_string(const std::string& in) {
    std::ostringstream out;
    JsonEscape(in, out);
    return out.str();
}

struct Logger {
    Logger(bool all = false) {
        logfault::LogManager::Instance().AddHandler(
            make_unique<JsonHandler>("json", out, LogLevel::DEBUGGING,
            all ? JsonHandler::all_fields : JsonHandler::default_fields));
    }

    ~Logger() {
        logfault::LogManager::Instance().RemoveHandler("json");
    }

    std::string get() const {
        return out.str();
    }

    std::stringstream out;
};

} // anon ns

TEST(JsonTests, SimpleOutput) {
    Logger log;

    LFLOG_INFO << "Hello there";

    const auto out = log.get();
    //clog << out << endl;
    EXPECT_NO_THROW(boost::json::parse(out));
}


TEST(JsonTests, OutputWithLocation) {
    Logger log;

    LFLOG_INFO_EX << "Hello there";

    const auto out = log.get();
    //clog << out << endl;
    EXPECT_NO_THROW(boost::json::parse(out));
}

TEST(JsonTests, OutputWithLocationAndSourcePosition) {
    Logger log{true};

    LFLOG_INFO_EX << "Hello there";

    const auto out = log.get();
    //clog << out << endl;
    EXPECT_NO_THROW(boost::json::parse(out));
}


int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}

// tests/cxx14/test_logfault_cxx14.cpp
#include <gtest/gtest.h>
#include "logfault/logfault.h"    // adjust include path if needed

#include <sstream>
#include <memory>

namespace {
  struct ClogRedirector {
    ClogRedirector(std::string& out, std::ostream& ios = std::clog)
    : out_{out}, ios_{ios} {
      orig_ = ios_.rdbuf(buffer_.rdbuf());
    }
    ~ClogRedirector() {
      out_ = buffer_.str();
      ios_.rdbuf(orig_);
    }
  private:
    std::ostream& ios_;
    std::streambuf* orig_;
    std::stringstream buffer_;
    std::string& out_;
  };
}  // namespace

TEST(LogfaultCxx14, InfoLevelEmitsMessage) {
  // make sure INFO is enabled
  logfault::LogManager::Instance().SetLevel(logfault::LogLevel::INFO);

  std::string captured;
  {
      ClogRedirector rdr(captured);
      LFLOG_INFO << "Hello C++14 test";
  }

  // The fallback mode always prefixes a timestamp and "INFO"
  EXPECT_NE(captured.find("INFO"), std::string::npos);
  EXPECT_NE(captured.find("Hello C++14 test"), std::string::npos);
}

TEST(LogfaultCxx14, DebugLevelSuppressedWhenAboveThreshold) {
  // set threshold to INFO, so DEBUG calls should vanish
  logfault::LogManager::Instance().SetLevel(logfault::LogLevel::INFO);

  std::string captured;
  {
    ClogRedirector rdr(captured);
    LFLOG_DEBUG << "this should NOT appear";
  }

  EXPECT_TRUE(captured.empty());
}

int main(int argc, char** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  // install a StreamHandler that writes to std::clog at TRACE level
  logfault::LogManager::Instance().AddHandler(
    std::make_unique<logfault::StreamHandler>(
      std::clog, logfault::LogLevel::TRACE
    )
  );
  return RUN_ALL_TESTS();
}


#include <iostream>

#define LOGFAULT_ENABLE_ALL
#include "logfault/logfault.h"

using namespace std;

int main( int argc, char *argv[]) {

    std::unique_ptr<logfault::Handler> filehandler{new logfault::StreamHandler(clog, logfault::LogLevel::TRACE)};

    logfault::LogManager::Instance().AddHandler(move(filehandler));

    LFLOG_DEBUG << "Testing" << 1 << 2 << 3;
    LFLOG_ERROR << "Did something fail?";

    LFLOG_IFALL_TRACE("Show only if enabled" << 1 << 3 << 5);
    LFLOG_IFALL_WARN("Show only if enabled" << " testme ");
}


#include <iostream>

#define LOGFAULT_ENABLE_ALL
#define LOGFAULT_USE_SYSLOG
#include "logfault/logfault.h"

using namespace std;

int main( int argc, char *argv[]) {

    std::unique_ptr<logfault::Handler> filehandler{new logfault::StreamHandler(clog, logfault::LogLevel::TRACE)};


    //logfault::LogManager::Instance().AddHandler(move(filehandler));

    std::unique_ptr<logfault::Handler> syslog_handler{ new logfault::SyslogHandler(logfault::LogLevel::DEBUG) };
    logfault::LogManager::Instance().AddHandler(move(syslog_handler));


    LFLOG_DEBUG << "Testing" << 1 << 2 << 3;
    LFLOG_ERROR << "Did something fail?";

    LFLOG_IFALL_TRACE("Show only if enabled" << 1 << 3 << 5);
    LFLOG_IFALL_WARN("Show only if enabled" << " testme ");
}

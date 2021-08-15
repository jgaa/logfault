
#include <iostream>

#define LOGFAULT_ENABLE_ALL
//#define LOGFAULT_USE_UTCZONE 1
//#define LOGFAULT_TIME_FORMAT "%c"
//#define LOGFAULT_TIME_PRINT_MILLISECONDS 0
//#define LOGFAULT_USE_SYSLOG
//#define LOGFAULT_USE_WINDOWS_EVENTLOG
//#define LOGFAULT_USE_THREAD_NAME
//#define LOGFAULT_USE_TID_AS_NAME
#include "logfault/logfault.h"

using namespace std;

int main( int argc, char *argv[]) {


    std::unique_ptr<logfault::Handler> filehandler{new logfault::StreamHandler(clog, logfault::LogLevel::TRACE)};
    logfault::LogManager::Instance().AddHandler(move(filehandler));

#ifdef LOGFAULT_USE_WINDOWS_EVENTLOG
	std::unique_ptr<logfault::Handler> eventhandler{new logfault::WindowsEventLogHandler("general_tests", logfault::LogLevel::DEBUG)};
	logfault::LogManager::Instance().AddHandler(move(eventhandler));
#endif

#ifdef LOGFAULT_USE_SYSLOG
    std::unique_ptr<logfault::Handler> syslog_handler{ new logfault::SyslogHandler(logfault::LogLevel::DEBUG) };
    logfault::LogManager::Instance().AddHandler(move(syslog_handler));
#endif


    std::unique_ptr<logfault::Handler> proxy_handler{ new logfault::ProxyHandler([](const logfault::Message& event) {

        cerr << "Log event: " << event.msg_ << std::endl;

    }, logfault::LogLevel::DEBUGGING)};
    logfault::LogManager::Instance().AddHandler(move(proxy_handler));


    LFLOG_DEBUG << "Testing" << 1 << 2 << 3;
    LFLOG_ERROR << "Did something fail?";

    LFLOG_IFALL_TRACE("Show only if enabled" << 1 << 3 << 5);
    LFLOG_IFALL_WARN("Show only if enabled" << " testme ");
}

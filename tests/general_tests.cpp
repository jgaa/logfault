
// General tests for manual testing during development

#include <iostream>

#define LOGFAULT_ENABLE_ALL
//#define LOGFAULT_USE_UTCZONE 1
//#define LOGFAULT_TIME_FORMAT "%c"
//#define LOGFAULT_TIME_PRINT_MILLISECONDS 0#define LOGFAULT_USE_SYSLOG
//#define LOGFAULT_USE_WINDOWS_EVENTLOG
//#define LOGFAULT_USE_THREAD_NAME
//#define LOGFAULT_USE_TID_AS_NAME
//#define LOGFAULT_USE_QT_LOG
//#define LOGFAULT_USE_SYSLOG 1
#include "logfault/logfault.h"

using namespace std;

int main( int argc, char *argv[]) {


    logfault::LogManager::Instance().AddHandler(std::make_unique<logfault::StreamHandler>(clog, logfault::LogLevel::TRACE));

#ifdef LOGFAULT_USE_WINDOWS_EVENTLOG
    logfault::LogManager::Instance().AddHandler(std::make_unique<logfault::WindowsEventLogHandler>("general_tests", logfault::LogLevel::DEBUGGING));
#endif

#ifdef LOGFAULT_USE_SYSLOG
    logfault::LogManager::Instance().AddHandler(std::make_unique<logfault::SyslogHandler>(logfault::LogLevel::DEBUGGING));
#endif

#ifdef LOGFAULT_USE_QT_LOG
    logfault::LogManager::Instance().AddHandler(std::make_unique<logfault::QtHandler>(logfault::LogLevel::DEBUGGING));
#endif

    logfault::LogManager::Instance().AddHandler(std::make_unique<logfault::ProxyHandler>([](const logfault::Message& event) {

        cerr << "Log event from proxy: " << event.msg_ << std::endl;

    }, logfault::LogLevel::DEBUGGING));


    LFLOG_DEBUG << "Testing" << 1 << 2 << 3;
    LFLOG_ERROR << "Did something fail?";

    LFLOG_IFALL_TRACE("Show only if enabled" << 1 << 3 << 5);
    LFLOG_IFALL_WARN("Show only if enabled" << " testme ");
}

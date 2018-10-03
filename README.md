# logfault

Simple to use, header only C++ library for application-logging on all major platforms.

No dependencies, except the standard-library for C++11 and platform dependent logging libraries, like `log` for Android.

# Why another C++ logging library?

Simply because I am tired of using different log methods on different platforms. Most of the C++ code I write is highly portable, and it makes sense to add logging in a convenient manner. For me that is to send the log to a std::ostream like device.

*Logfault* can write log-events to traditional log-files, but it's also capable of using the native logging facility for the target platform for the target application. That meas that you can write your C++ library, and then let the consumer of the library configure logging for the platform they build it for.

**Why not just use Boost.Log**? First of all - I don't like it. I find it over-engendered. It don't flush the log automatically. And - more importantly - a lot of projects don't use the boost library. It's a pain to use with Android NDK or IOS - and it's time-consuming to compile and include it in projects even on Windows.

For example - I currently develop a general C++ library under Linux, with few dependencies and no use of boost. It use CMake, and when I build it for testing, I log to std::clog, and inspect the logs in *kdevelop*. The library is used by apps for IOS and Android.

## Configure log targets and log levels

Log targets can be configured in C++ code, as part of the initialization of your library, or application, or the log setup can be wrapped to the target platform's language(s).

### IOS and macos targets

Under IOS, the app developers for my library use a tiny wrapper I wrote in Objective-C to enable logging and chose log level, either from Objective-C or Swift.

Objective C, header file: `LogWrapper.h`
```Objective-C
typedef enum {
    LOG_NORMAL,
    LOG_DEBUG,
    LOG_TRACE
} LogLevel;

#if defined __cplusplus
extern "C" {
#endif

void SetLogLevel(LogLevel level);

#if defined __cplusplus
};
#endif
```

The implementation: `LogWrapper.mm`

```Objective-C
#include "LogWrapper.h"

#define LOGFAULT_USE_COCOA_NLOG_IMPL
#include "logfault/logfault.h"

void SetLogLevel(LogLevel level) {

    logfault::LogLevel use_level = logfault::LogLevel::INFO;

    switch(level) {
        case LOG_DEBUG:
            use_level = logfault::LogLevel::DEBUG;
            break;
        case LOG_TRACE:
            use_level = logfault::LogLevel::TRACE;
            break;
        case LOG_NORMAL:
            break; // default
    }

    logfault::LogManager::Instance().AddHandler(std::make_unique<logfault::CocoaHandler>(use_level));
}
```

Swift code to set the log-level:
```swift
SetLogLevel(LOG_TRACE);
```

That's it. This Objective-C code enables logging trough NSLog for IOS (and macos, it that's your target).

### Android NDK targets

Under Android, I made a similar wrapper that let the Android app developers enable the log and set the level they want from Java.

Header file: `Logger.h`
```C++
pragma once

enum LogLevel  { LOG_NORMAL, LOG_DEBUG, LOG_TRACE };

void SetLogLevel(LogLevel level);
```

C++ file `Logger.cpp`
```C++
#include "Logger.h"

#define LOGFAULT_USE_ANDROID_NDK_LOG
#include "logfault/logfault.h"

void SetLogLevel(LogLevel level) {
    logfault::LogLevel use_level = logfault::LogLevel::INFO;

    switch(level) {
        case LOG_DEBUG:
            use_level = logfault::LogLevel::DEBUG;
            break;
        case LOG_TRACE:
            use_level = logfault::LogLevel::TRACE;
            break;
        case LOG_NORMAL:
            break; // default
    }

    logfault::LogManager::Instance().AddHandler(std::make_unique<logfault::AndroidHandler>(
        "nynja-wallet", use_level));
}
```

Swig code to generate wrapper code in Java
```swig
%module LoggerModule

%include "enums.swg"

%{
#include "./Logger.h"
%}

%include "./Logger.h"

```

That's it. Once compiled and loaded into the Android app, you can set enable the logging using Android NDK's log library with this Java statement:

```java
LoggerModule.SetLogLevel(LogLevel.LOG_DEBUG);

```

## Linux, Unix, syslog

If you want to log to the syslog under Linux or Unix, just set up logging as this:

```C++
// Enable syslog
#define LOGFAULT_USE_SYSLOG

#include "logfault/logfault.h"
using namespace std;

int main() {

    // Set up a log-handler to syslog
    logfault::LogManager::Instance().AddHandler(make_unique<SyslogHandler>(logfault::LogLevel::DEBUG));

    LFLOG_DEBUG << "Logging to syslog is enabled at DEBUG level";
}

```

## Log to stdout

Similarly, if you just want to log to standard output:

```C++
#include "logfault/logfault.h"
using namespace std;

int main() {

    // Set up a log-handler to stdout
    logfault::LogManager::Instance().AddHandler(make_unique<StreamHandler>(clog, logfault::LogLevel::TRACE));

    LFLOG_DEBUG << "Logging to std::clog is enabled at DEBUG level";
}

```

## Multiple log-targets

If you want to log to several targets at once, you can also do that:

```C++
// Enable syslog
#define LOGFAULT_USE_SYSLOG

#include "logfault/logfault.h"
using namespace std;

int main() {

    // Set up a log-handler to syslog
    logfault::LogManager::Instance().AddHandler(make_unique<SyslogHandler>(logfault::LogLevel::DEBUG));
    LFLOG_DEBUG << "Logging to syslog is enabled at DEBUG level";

    // Set up a log-handler to stdout
    logfault::LogManager::Instance().AddHandler(make_unique<StreamHandler>(clog, logfault::LogLevel::TRACE));
    LFLOG_DEBUG << "Logging to std::clog is enabled at TRACE level";
}

```

In the last example, you will log to syslog at DEBUG level (all log messages, except those at trace - very verbose - level)
and all log messages to stdout.

## Logging

When you log messages, you stream data into a temporary std::ostream object. So everything that goes into a std::ostream instance can be logged.
I often find myself writing custom std::ostream operators to log things like enum names and internal data structures or
object identifies.

*Logfault* has two types of log macros. You have normal log macros, that are used like this:

```C++
LFLOG_ERROR << "Some error occurred: " << errno;
LFLOG_DEBUG << "We are entering foo foo";
```

These macros expand to something like:
```C++
if (log_event_log_level is within current_log_level_range
    and we_are_indeed_logging) {

    logstream << args ...;
}
```

In other words, the streaming arguments will be ignored (and function arguments not called) unless we will actually log the line.
If the log-level is set to NOTICE, all DEBUG and TRACE messages will be totally ignored and not consume any CPU. The
only CPU consumed for such log statements is the check to see if the log statements are relevant.

Usually this is fine. However, some times we need a lot of log statements to understand the cause of some weird bug.
Normally I don't even want those log statements to be evaluated for relevance. For those statements, we have
another type of log macros:

```C++
LFLOG_IFALL_TRACE("Show only if enabled" << 1 << 3 << 5);
```

Notice that the whole log statement is enclosed by `(` and `)`. These log statements are simply removed by
the C++ preprocessor, unless `LOGFAULT_ENABLE_ALL` is defined when `logfault.h` is included.

The full set of log-macros are:

**`LFLOG_ERROR`** Errors
**`LFLOG_WARN`** Warnings
**`LFLOG_NOTICE`** Notable events
**`LFLOG_INFO`** Information about what's going on
**`LFLOG_DEBUG`** Debug messages
**`LFLOG_TRACE`** Trace messages. These may give very detailed information about what's going on


And a similar set of conditional macros that require `LOGFAULT_ENABLE_ALL` in order to work.

**`LFLOG_IFALL_ERROR()`** Errors
**`LFLOG_IFALL_WARN()`** Warnings
**`LFLOG_IFALL_NOTICE()`** Notable events
**`LFLOG_IFALL_INFO()`** Information about what's going on
**`LFLOG_IFALL_DEBUG()`** Debug messages
**`LFLOG_IFALL_TRACE()`** Trace messages. These may give very detailed information about what's going on


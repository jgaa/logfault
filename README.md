# logfault

Simple to use, header only C++ library for application-logging on all major platforms.

No dependencies, except the standard-library for C++11 and platform dependent logging libraries, like `log` for Android.

# Why another C++ logging library?

Simply because I am tired of using different log methods on different platforms. Most of the C++ code I write is highly portable, and it makes sense to add logging in a convenient manner. For me that is to send the log to a std::ostream like device. Logging should be as easy as writing to `std::cout`!

*Logfault* can write log-events to traditional log-files, but it's also capable of using the native logging facility for the target platform for the target application. That meas that you can write your C++ library, and then let the consumer of the library configure logging for the platform they build it for.

**Why not just use Boost.Log**? First of all - I don't like it. I find it over-engineered. It don't flush the log automatically. And - more importantly - a lot of projects don't use the boost library. It's a pain to use with Android NDK or IOS - and it's time-consuming to compile and include it in projects even on Windows.

For example - I currently develop a general C++ library under Linux, with few dependencies and no use of boost. It use CMake, and when I build it for testing, I log to std::clog, and inspect the logs in *kdevelop*. The library is used by apps for IOS and Android. Adding a dependency to Boost just to get the Boost.Log library may
be more work than it's worth.

*Logfaut* is not meant as a replacement of a sophisticated logger for a large application. It's more like a
hack to get logging right, in libraries, smaller applications and mobile apps written in C++. It was written
in a few hours when I desperately needed to get log-output from the C++ library for Android and IOS mentioned above.
In the following days I have spent a few extra hours to make it a little more mature, and hopefully useful for other developers as well.

# What are the benefits of logfault?

- Header only library.
- Very, very easy to use: `LFLOG_DEBUG << "We are entering foo foo: " << 1 << 2 << 3;`
- Compact, less that 400 lines of code - including blank lines and comments.
- Designed to make a tiny binary footprint; ideal for mobile and IoT.
- Ideal for X-platform apps and libraries; logs to files, syslog, IOS/macOS `NSLog()`, Android's `__android_log_write()`, QT log macros and the Windows EventLog.
- Log statements are not evaluated unless they will be logged (filtered by log-level)
- Uses the C++ preprocessor to totally remove verbose log statements when you don't need them.
- Flexible time-stamps, easy to use local-time or UTC.
- Can log to several log-targets at different log-levels.
- Written by someone who has worked extensively with logging for decades (from tiny libraries and applications, to owning the log/event libraries in a two digits multi million line C++ application from one of the largest software vendors in the world).

# When should you not use logfault?
- In applications and servers that normally logs *lots* of information. *Logfault* is optimized for moderate log-volumes and occasional debugging session with extensive logging. The reason is that it use std::stream's which are relatively slow compared to raw buffer-based IO.

# Logging

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

## The full set of log-macros

- **`LFLOG_ERROR`** Errors
- **`LFLOG_WARN`** Warnings
- **`LFLOG_NOTICE`** Notable events
- **`LFLOG_INFO`** Information about what's going on
- **`LFLOG_DEBUG`** Debug messages
- **`LFLOG_TRACE`** Trace messages. These may give very detailed information about what's going on


And a similar set of conditional macros that require `LOGFAULT_ENABLE_ALL` in order to work.

- **`LFLOG_IFALL_ERROR()`** Errors
- **`LFLOG_IFALL_WARN()`** Warnings
- **`LFLOG_IFALL_NOTICE()`** Notable events
- **`LFLOG_IFALL_INFO()`** Information about what's going on
- **`LFLOG_IFALL_DEBUG()`** Debug messages
- **`LFLOG_IFALL_TRACE()`** Trace messages. These may give very detailed information about what's going on


# Configure log targets and log levels

A log target is somewhere to deliver the log events, like a file on disk, or a log application
like syslog.

*Logfault* use instances of log handlers to configure the targets.

Log targets can be configured in C++ code, as part of the initialization of your library,
or application, or the log setup can be wrapped to the target platform's language(s).

It's simple to create [initialization functions for other languages](doc/control_wrappers.md).

## Log to stdout or file

If you just want to log to standard output:

```C++
#include "logfault/logfault.h"
using namespace std;

int main() {

    // Set up a log-handler to stdout
    logfault::LogManager::Instance().AddHandler(make_unique<StreamHandler>(clog, logfault::LogLevel::TRACE));

    LFLOG_DEBUG << "Logging to std::clog is enabled at DEBUG level";
}

```
You can of course replace `clog` with any `std::ostream`, for example an open file to write to.

## Linux, Unix, syslog

If you want to log to the syslog under Linux or Unix, just set up logging like this:

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

## Windows EventLog
The library can send log-events to the Windows EventLog under Windows.

If you want to do it properly, you need to create a  message template file, compile it,
include it in the Visual Studio project, and then add it in the registry on the
computers that will run the application. For obvious reasons, most applications don't
do that, and the events are polluted by the message:

    The description for Event ID 0 from source general_tests cannot be found. Either the component that raises this event is not installed on your local computer or the installation is corrupted. You can install or repair the component on the local computer.

    If the event originated on another computer, the display information had to be saved with the event.

    The following information was included with the event:

This is fine. Even large Windows application vendors ignores this inconvenience in their logging.
Blame Microsoft for making it very hard to support the EventLog in 3rd party applications.

Example of application logging to the Windows EventLog:

```C++
#define LOGFAULT_USE_WINDOWS_EVENTLOG
#include "logfault/logfault.h"

int main( int argc, char *argv[]) {
    std::unique_ptr<logfault::Handler> eventhandler{new logfault::WindowsEventLogHandler("example", logfault::LogLevel::DEBUG)};
    logfault::LogManager::Instance().AddHandler(move(eventhandler));

    LFLOG_DEBUG << "Logging to the Windows EventLog is enabled at DEBUG level";
}
```

## Log via QT's qDebug() and friends

This will simply send the log events to QT's logging macros, allowing any
log-configuration for the QT application to also apply for *logfault*.

It may be useful if you include non-QT libaries using *logfault*
into a QT application.

```C++
#define LOGFAULT_USE_QT_LOG
#include "logfault/logfault.h"

int main( int argc, char *argv[]) {
    logfault::LogManager::Instance().AddHandler(std::make_unique<logfault::QtHandler>(
        logfault::LogLevel::DEBUG));

    LFLOG_DEBUG << "Logging to QT's log macros is enabled at DEBUG level";
}
```


## Log via Android NDK's log library

In Android, native applications must use a primitive log library
that is bundled with the NDK if they need to log anything to the
Android system log. *Logfault* has a handler that can do that
for us.

```C++
#define LOGFAULT_USE_ANDROID_NDK_LOG
#include "logfault/logfault.h"

int main( int argc, char *argv[]) {
    logfault::LogManager::Instance().AddHandler(std::make_unique<logfault::AndroidHandler>(
        "my-app", logfault::LogLevel::DEBUG));

    LFLOG_DEBUG << "Logging to Android logcat is enabled at DEBUG level";
}
```

## Log via IOS and macOS' NSLog

The logging support for IOS and macOS is rather primitive, compared to other systems.
The good thing is that when you debug an application in Xcode, you can see the output
from the applications standard output - so you don't really *need* to use the `NSLog` funtion.

However, if you want to do it *right*, you log via `NSLog`, and *logfault* can help us with that.

```C++
#define LOGFAULT_USE_COCOA_NLOG_IMPL
#include "logfault/logfault.h"

int main( int argc, char *argv[]) {
    logfault::LogManager::Instance().AddHandler(std::make_unique<logfault::CocoaHandler>(
        logfault::LogLevel::DEBUG));

    LFLOG_DEBUG << "Logging to IOS/ macOS NSLog() is enabled at DEBUG level";
}
```

**Please notice** that for NSLog to work, you need to define `LOGFAULT_USE_COCOA_NLOG_IMPL` before including
`logfault.h` in *one* .mm file. This is because of how the Apple development tools deal with Objective-C and
C++. We cannot reach the Cocoa function `NSLog` from C++ code - only from Objective-C++. And since we need
C++ code to define the Cocoa handler, the implementation needs to go in *one* .mm file. You can create an
empty .mm file for this purpose, or use an existing one.

## Log via another log-system

It's normal for a log-library to have a means of chaining log events to some other log framework.
*Logfault* have a proxy handler where you can direct the log messages wherever you like.

```C++
#include "logfault/logfault.h"
using namespace std;

int main() {

    // Set up a log-handler to a lambda function
    logfault::LogManager::Instance().AddHandler(make_unique<ProxyHandler>([](const logfault::Message& event) {

        // Here, you could send the log-event to whatever you want
        cerr << "Log event: " << event.msg_ << std::endl;

    }, logfault::LogLevel::DEBUG));

    LFLOG_DEBUG << "Logging to proxy is enabled at DEBUG level";
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

# Date and time formatting

By default, *logfault* write a time-stamp like this `2018-10-10 09:26:46.821 EEST`.

You can tweak that a bit with the following macros

- **`LOGFAULT_USE_UTCZONE`** If 1, the time-stamp will be in UTC, else it will be in the local timezone. The default is 0.
- **`LOGFAULT_TIME_FORMAT`** [Time format string](https://en.cppreference.com/w/cpp/io/manip/put_time) to use. The default is `"%Y-%m-%d %H:%M:%S."`.
- **`LOGFAULT_TIME_PRINT_MILLISECONDS`** If 1, adds a 3-digit milliseconds count after the formatted date / time. The default is 1.
- **`LOGFAULT_TIME_PRINT_TIMEZONE`** If 1, adds the time-zone after the formatted date / time and milliseconds count. The default is 1.

Note that the time-stamp is only used when *logfault* formats the log-message. If the log-event is passed to
a native log-handler, that handler will format the date and time according to it's own preferences.


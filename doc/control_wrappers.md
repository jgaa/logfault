# Enabling loggers from non C++ languages

To enable logging in an application, we must instantiate a log handler with the
desired log level, and then add it to the list of log handlers in the `LogManager`.

This is simple to do in C++. However, if the logging is used in a C++ library that is
used by for example a Java or Swift application, we may want to make initialization
available in that language.

## IOS and macOS targets

Under IOS, the app developers for my library use a tiny wrapper I wrote in
Objective-C to enable logging and chose log level, either from Objective-C
or Swift.

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

**Please notice** that for NSLog to work, you need to define `LOGFAULT_USE_COCOA_NLOG_IMPL` before including
`logfault.h` in *one* .mm file. This is because of how the Apple development tools deal with Objective-C and
C++. We cannot reach the Cocoa function `NSLog` from C++ code - only from Objective-C. And since we need
C++ code to define the Cocoa handler, the implementation needs to go in *one* .mm file. You can create an
empty .mm file for this purpose, or use an existing one.

Swift code to set the log-level:
```swift
SetLogLevel(LOG_TRACE);
```

That's it. This Objective-C code enables logging trough NSLog for IOS (and macos, it that's your target).


## Android NDK targets

Under Android, I made a similarwrapper that let the Android app developers enable the log and set the level they want from Java.

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

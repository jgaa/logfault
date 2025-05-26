#pragma once

/*
MIT License

Copyright (c) 2018 - 2021 Jarle Aase

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

Home: https://github.com/jgaa/logfault
*/

#ifndef _LOGFAULT_H
#define _LOGFAULT_H

#include <array>
#include <assert.h>
#include <chrono>
#include <fstream>
#include <functional>
#include <iomanip>
#include <memory>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#if __cplusplus >= 202002L
#   include <string_view>
#endif

#ifndef LOGFAULT_USE_UTCZONE
#   define LOGFAULT_USE_UTCZONE 0
#endif

#ifndef LOGFAULT_TIME_FORMAT
#   define LOGFAULT_TIME_FORMAT "%Y-%m-%d %H:%M:%S."
#endif

#ifndef LOGFAULT_TIME_PRINT_MILLISECONDS
#   define LOGFAULT_TIME_PRINT_MILLISECONDS 1
#endif

#ifndef LOGFAULT_TIME_PRINT_TIMEZONE
#   define LOGFAULT_TIME_PRINT_TIMEZONE 1
#endif

#ifdef LOGFAULT_USE_SYSLOG
#   include <syslog.h>
#endif

#ifdef LOGFAULT_USE_ANDROID_NDK_LOG
#   include <android/log.h>
#endif

#ifdef LOGFAULT_USE_QT_LOG
#   include <QDebug>
#endif

#ifdef LOGFAULT_USE_WINDOWS_EVENTLOG
#	include <windows.h>

// Thank you soo much Microsoft!
#	undef ERROR
#endif

#ifndef LOGFAULT_LOCATION__
#   if defined(LOGFAULT_ENABLE_LOCATION) && LOGFAULT_ENABLE_LOCATION
#       define LOGFAULT_LOCATION__ << logfault::Handler::ShortenPath(__FILE__) << ':' << __LINE__ << " {" << __func__ << "} "
#       ifndef LOGFAULT_LOCATION_LEVELS
#           define LOGFAULT_LOCATION_LEVELS 3
#       endif
#   else
#       define LOGFAULT_LOCATION__
#   endif
#endif

#ifndef LOGFAULT_LOCATION_LEVELS
#   define LOGFAULT_LOCATION_LEVELS 3
#endif

// Internal implementation detail
#define LOGFAULT_LOG__(level) \
    ::logfault::validLevel(level) && \
    ::logfault::LogManager::Instance().IsRelevant(level) && \
    ::logfault::Log(level).Line() LOGFAULT_LOCATION__

#define LFLOG_ERROR LOGFAULT_LOG__(logfault::LogLevel::ERROR)
#define LFLOG_WARN LOGFAULT_LOG__(logfault::LogLevel::WARN)
#define LFLOG_NOTICE LOGFAULT_LOG__(logfault::LogLevel::NOTICE)
#define LFLOG_INFO LOGFAULT_LOG__(logfault::LogLevel::INFO)
#define LFLOG_DEBUG LOGFAULT_LOG__(logfault::LogLevel::DEBUGGING)
#define LFLOG_TRACE LOGFAULT_LOG__(logfault::LogLevel::TRACE)

#if defined(__clang__) || defined(__GNUC__)
#  define LOGFAULT_FUNC_NAME  __PRETTY_FUNCTION__
#elif defined(_MSC_VER)
#  define LOGFAULT_FUNC_NAME  __FUNCSIG__
#else
#  define LOGFAULT_FUNC_NAME  __func__
#endif

#if __cplusplus >= 202002L
#define LOGFAULT_LOG_EX__(level, ...) \
    ::logfault::validLevel(level) && \
    ::logfault::LogManager::Instance().IsRelevant(level) && \
    ::logfault::Log(level, __FILE__, __LINE__, LOGFAULT_FUNC_NAME __VA_OPT__(, __VA_ARGS__)  ).Line()

// Signature for the toLog function
// std::pair<bool /* json */, std::string /* content or json */>(const auto& data, bool /*want json*/)
template <typename T>
std::pair<bool /* json */, std::string /* content or json */>
toLog(const T& data, const bool want_json = false) {
    if constexpr (std::is_same_v<T, std::string_view> || std::is_same_v<T, std::string>) {
        return {false, data};
    } else if constexpr (!std::is_same_v<T, std::string_view> && !std::is_same_v<T, std::string>) {
        return {false, std::to_string(data)};
    }
}

#else
#define LOGFAULT_LOG_EX__(level) \
    ::logfault::validLevel(level) && \
    ::logfault::LogManager::Instance().IsRelevant(level) && \
    ::logfault::Log(level, __FILE__, __LINE__, LOGFAULT_FUNC_NAME).Line()
#endif


#define LFLOG_ERROR_EX LOGFAULT_LOG_EX__(logfault::LogLevel::ERROR)
#define LFLOG_WARN_EX LOGFAULT_LOG_EX__(logfault::LogLevel::WARN)
#define LFLOG_NOTICE_EX LOGFAULT_LOG_EX__(logfault::LogLevel::NOTICE)
#define LFLOG_INFO_EX LOGFAULT_LOG_EX__(logfault::LogLevel::INFO)
#define LFLOG_DEBUG_EX LOGFAULT_LOG_EX__(logfault::LogLevel::DEBUGGING)
#define LFLOG_TRACE_EX LOGFAULT_LOG_EX__(logfault::LogLevel::TRACE)

#ifdef LOGFAULT_ENABLE_ALL
#   define LFLOG_IFALL_ERROR(msg) LFLOG_ERROR << msg
#   define LFLOG_IFALL_WARN(msg) LFLOG_WARN << msg
#   define LFLOG_IFALL_NOTICE(msg) LFLOG_NOTICE << msg
#   define LFLOG_IFALL_INFO(msg) LFLOG_INFO << msg
#   define LFLOG_IFALL_DEBUG(msg) LFLOG_DEBUG << msg
#   define LFLOG_IFALL_TRACE(msg) LFLOG_TRACE << msg
# else
#   define LFLOG_IFALL_ERROR(msg)
#   define LFLOG_IFALL_WARN(msg)
#   define LFLOG_IFALL_NOTICE(msg)
#   define LFLOG_IFALL_INFO(msg)
#   define LFLOG_IFALL_DEBUG(msg)
#   define LFLOG_IFALL_TRACE(msg)
#endif

#ifndef LOGFAULT_THREAD_NAME
#   if defined (LOGFAULT_USE_THREAD_NAME)
#       include <pthread.h>
        inline const char *logfault_get_thread_name_() noexcept {
            thread_local std::array<char, 16> buffer = {};
            if (pthread_getname_np(pthread_self(), buffer.data(), buffer.size()) == 0) {
                return buffer.data();
            }
            return "err pthread_getname_np";
        }
#       define LOGFAULT_THREAD_NAME logfault_get_thread_name_()
#
#   elif defined(LOGFAULT_USE_TID_AS_NAME)  && defined(__linux__)
#       include <unistd.h>
#       include <sys/syscall.h>
#       define LOGFAULT_THREAD_NAME syscall(__NR_gettid)
#   elif defined(LOGFAULT_USE_TID_AS_NAME)  && defined(__unix__)
#       include <pthread.h>
#       define LOGFAULT_THREAD_NAME pthread_self()
#   elif defined(LOGFAULT_USE_TID_AS_NAME)  && defined(WIN32)
#       include <windows.h>
#       define LOGFAULT_THREAD_NAME GetCurrentThreadId()
#   else
#       define LOGFAULT_THREAD_NAME std::this_thread::get_id()
#   endif
#endif

#ifdef ERROR
// Thank you SOOO much Microsoft!
#   undef ERROR
#endif


namespace logfault {

    enum class LogLevel { DISABLED, ERROR, WARN, NOTICE, INFO, DEBUGGING, TRACE };

    // Allows us to optimize log statements below a treashold away from the compiled code.
    // Good for release builds to for example totally remove trace messages.
    constexpr bool validLevel(LogLevel level) {
#if defined(LOGFAULT_MIN_LOG_LEVEL)
        return level != LogLevel::DISABLED && level <= LogLevel::LOGFAULT_MIN_LOG_LEVEL;
#else
        return level != LogLevel::DISABLED;
#endif
    }

    template<typename T>
    std::string ThreadNameToString(T tid) {
        std::ostringstream out;
        out << tid;
        return out.str();
    }

    struct Extra {
        std::string content;
        std::string json;
    };

    template <typename T>
    void JsonEscape(const T& msg, std::ostream& out) {
        // Lookup table for hex digits
        static constexpr char hex[] = "0123456789ABCDEF";

        // TODO: Use a static lookup table in stead of many tests
        for (const char c : msg) {
            unsigned char uc = static_cast<unsigned char>(c);
            if (c > '"' && c != '\\') [[likely]] {
                out.put(c);
                continue;
            }
            switch (c) {
            case '\"': out.put('\\'); out.put('\"'); break;
            case '\\': out.put('\\'); out.put('\\'); break;
            case '\b': out.put('\\'); out.put('b');  break;
            case '\f': out.put('\\'); out.put('f');  break;
            case '\n': out.put('\\'); out.put('n');  break;
            case '\r': out.put('\\'); out.put('r');  break;
            case '\t': out.put('\\'); out.put('t');  break;
            default:
                if (uc < 0x20) [[unlikely]] {
                    // control characters as \u00XX
                    out.put('\\'); out.put('u');
                    out.put('0');  out.put('0');
                    out.put(hex[(uc >> 4) & 0xF]);
                    out.put(hex[ uc       & 0xF]);
                } else {
                    // regular printable character
                    out.put(c);
                }
            }
        }
    }

    struct Message {
        using extras_t = std::function<Extra(bool wantJson)>;
        Message(const std::string && msg, const LogLevel level, const char *file = nullptr
                , const int line = 0, const char *func = nullptr, const extras_t& log_fn = nullptr)
            : msg_{std::move(msg)}, level_{level}, file_{file}, line_{line}, func_{func}, log_fn_{log_fn} {}

        const std::string msg_;
        const std::chrono::system_clock::time_point when_ = std::chrono::system_clock::now();
        const LogLevel level_;
        const char *file_{};
        const int line_{};
        const char *func_{};
        const extras_t& log_fn_ {};
        const std::string thread_{ThreadNameToString(LOGFAULT_THREAD_NAME)};
    };

    class Handler {
    public:
        Handler(LogLevel level = LogLevel::INFO) : level_{level} {}
        virtual ~Handler() = default;
        using ptr_t = std::unique_ptr<Handler>;

        virtual void LogMessage(const Message& msg) = 0;
        const LogLevel level_;

// check if c++20 or later
#if __cplusplus >= 202002L
        static std::string_view LevelName(const LogLevel level) {
            static constexpr std::array<std::string_view, 7> names =
                {{"DISABLED", "ERROR", "WARNING", "NOTICE", "INFO", "DEBUGGING", "TRACE"}};
            return names.at(static_cast<size_t>(level));
        }
#else
        static const char * LevelName(const LogLevel level) {
            static const std::array<const char *, 7> names =
                {{"DISABLED", "ERROR", "WARNING", "NOTICE", "INFO", "DEBUGGING", "TRACE"}};
            return names.at(static_cast<size_t>(level));
        }
#endif

        void PrintTime(std::ostream& out, const logfault::Message& msg) {
            auto tt = std::chrono::system_clock::to_time_t(msg.when_);
            auto when_rounded = std::chrono::system_clock::from_time_t(tt);
            if (when_rounded > msg.when_) {
                --tt;
                when_rounded -= std::chrono::seconds(1);
            }
            if (const auto tm = (LOGFAULT_USE_UTCZONE ? std::gmtime(&tt) : std::localtime(&tt))) {
                const int ms = std::chrono::duration_cast<std::chrono::duration<int, std::milli>>(msg.when_ - when_rounded).count();

                out << std::put_time(tm, LOGFAULT_TIME_FORMAT)
#if LOGFAULT_TIME_PRINT_MILLISECONDS
                    << std::setw(3) << std::setfill('0') << ms
#endif
#if LOGFAULT_TIME_PRINT_TIMEZONE
#   if LOGFAULT_USE_UTCZONE
                    << " UTC";
#   else
                    << std::put_time(tm, " %Z")
#   endif
#endif
                ;
            } else {
                out << "0000-00-00 00:00:00.000";
            }

        }

        void PrintMessage(std::ostream& out, const logfault::Message& msg) {
            PrintTime(out, msg);

            out << ' ' << LevelName(msg.level_)
                << ' ' << LOGFAULT_THREAD_NAME;

            if (msg.func_) {
                out << " {" << msg.func_ << '}';
            }

            if (msg.log_fn_) {
                Extra extra = msg.log_fn_(false);
                out << ' ' << extra.content;
            }

            out  << ' ' << msg.msg_;
        }

        static const char *ShortenPath(const char *path) {
            assert(path);
            if (LOGFAULT_LOCATION_LEVELS <= 0) {
                return path;
            }
            std::vector<const char *> seperators;
            for(const char *p = path; *p; ++p) {
                if (((*p == '/')
#if defined(WIN32) || defined(__WIN32) || defined(MSC_VER) || defined(WINDOWS)
                    || (*p == '\\')
#endif
                ) && p[1]) {
                    if (seperators.size() > LOGFAULT_LOCATION_LEVELS) {
                        seperators.erase(seperators.begin());
                    }
                    seperators.push_back(p + 1);
                }
            }
            return seperators.empty() ? path : seperators.front();
        }

    };

    class StreamHandler : public Handler {
    public:
        StreamHandler(std::ostream& out, LogLevel level) : Handler(level), out_{out} {}
        StreamHandler(const std::string& path, LogLevel level, const bool truncate = false) : Handler(level)
        , file_{new std::ofstream{path, std::ios::out | (truncate ? std::ios::trunc : std::ios::app)}}, out_{*file_} {}

        void LogMessage(const Message& msg) override {
            PrintMessage(out_, msg);
            out_ << std::endl;
        }

    private:
        std::unique_ptr<std::ostream> file_;
        std::ostream& out_;
    };

    class JsonHandler : public Handler {
    public:
        enum Fields {
            TIME, LEVEL, THREAD, FILE, LINE, FUNC, MSG
        };

        // trace, debug, info, warn, error, fatal

        static constexpr int default_fields = 1 << Fields::TIME
                                              | 1 << Fields::LEVEL
                                              | 1 << Fields::THREAD
                                              | 1 << Fields::FUNC
                                              | 1 << Fields::MSG;

        JsonHandler(std::ostream& out, LogLevel level, int fields = default_fields)
            : Handler(level), out_{out}, fields_{fields} {}

        JsonHandler(const std::string& path, LogLevel level, int fields = default_fields, const bool truncate = false)
            : Handler(level)
            , file_{new std::ofstream{path, std::ios::out | (truncate ? std::ios::trunc : std::ios::app)}}
            , out_{*file_}, fields_{fields} {
            if (!file_->is_open()) {
                throw std::runtime_error{"Failed to open file: " + path};
            }
        }

        void LogMessage(const Message& msg) override {
        // Use severity level names recognized by Grafana
#if __cplusplus >= 202002l
            static constexpr std::array<std::string_view, 7> names =
#else
            static const std::array<const char *, 7> names =
#endif
            {{"disabled", "error", "warn", "info", "info", "debug", "trace"}};

            std::optional<Extra> extra;

            if (msg.log_fn_) {
                extra = msg.log_fn_(true);
            }

            bool first = true;
            auto add = [&](const char *name, const char *value) {
                if (first) [[unlikely]] {
                    first = false;
                } else {
                    out_ << ',';
                }
                out_ << '"' << name << "\":\"";

                if (value) {
                    out_ << value << '"';
                }
            };

            auto add_json = [&](const auto json) {
                if (first) [[unlikely]] {
                    first = false;
                } else {
                    out_ << ',';
                }
                out_ << json;
            };

            out_ << '{';

            if (fields_ & (1 << Fields::TIME)) {
                add("time", {});
                PrintTime(out_, msg);
                out_ << '"';
            }

            if (fields_ & (1 << Fields::LEVEL)) {
                add("level", {});
                assert(static_cast<unsigned int>(msg.level_) < names.size() && "LogLevel out of range");
                out_ << names[static_cast<unsigned int>(msg.level_)] << '"';
            }

            if (fields_ & (1 << Fields::THREAD)) {
                add("thread", {});
                out_ << LOGFAULT_THREAD_NAME << '"';
            }

            if (fields_ & (1 << Fields::FILE) && msg.file_) {
                add("src_file", ShortenPath(msg.file_));
            }

            if (fields_ & (1 << Fields::LINE) && msg.line_) {
                add("src_line", {});
                out_ << msg.line_ << '"';
            }

            if (fields_ & (1 << Fields::FUNC) && msg.func_) {
                add("func", msg.func_);
            }

            if (extra && !extra->json.empty()) {
                add_json(extra->json);
            }

            if (fields_ & (1 << Fields::MSG)) {
                add("log", {});
                JsonEscape(msg.msg_, out_);
                if (extra && !extra->content.empty()) {
                    out_ << ' ' << extra->content;
                }
                out_ << '"';
            }

            out_ << '}' << std::endl;
        }

    private:
        std::unique_ptr<std::ofstream> file_;
        std::ostream& out_;
        const int fields_{};
    };

    class ProxyHandler : public Handler {
    public:
        using fn_t = std::function<void(const Message&)>;

        ProxyHandler(const fn_t& fn, LogLevel level) : Handler(level), fn_{fn} {
            assert(fn_);
        }

        void LogMessage(const logfault::Message& msg) override {
            fn_(msg);
        }

    private:
        const fn_t fn_;
    };

#ifdef LOGFAULT_USE_SYSLOG
    class SyslogHandler : public Handler {
    public:
        SyslogHandler(LogLevel level, int facility = LOG_USER)
        : Handler(level) {
            static std::once_flag syslog_opened;
            std::call_once(syslog_opened, [facility] {
                openlog(nullptr, 0, facility);
            });
        }

        void LogMessage(const logfault::Message& msg) override {
            static const std::array<int, 6> syslog_priority =
                { LOG_ERR, LOG_WARNING, LOG_NOTICE, LOG_INFO, LOG_DEBUG, LOG_DEBUG };

            syslog(syslog_priority.at(static_cast<int>(level_)), "%s", msg.msg_.c_str());
        }
    };
#endif

#ifdef LOGFAULT_USE_ANDROID_NDK_LOG
    class AndroidHandler : public Handler {
    public:
        AndroidHandler(const std::string& name, LogLevel level)
        : Handler(level), name_{name} {}

        void LogMessage(const logfault::Message& msg) override {
            static const std::array<int, 7> android_priority =
                { ANDROID_LOG_SILENT, ANDROID_LOG_ERROR, ANDROID_LOG_WARN, ANDROID_LOG_INFO,
                  ANDROID_LOG_INFO, ANDROID_LOG_DEBUG, ANDROID_LOG_VERBOSE };

            std::ostringstream out;
            PrintMessage(out, msg);
            const auto out_str = out.str();
            __android_log_write(android_priority.at(static_cast<int>(level_)),
                                name_.c_str(), out_str.c_str());
        }

    private:
        const std::string name_;
    };
#endif

#ifdef LOGFAULT_USE_QT_LOG
    class QtHandler : public Handler {
    public:
        QtHandler(LogLevel level)
        : Handler(level) {}

        void LogMessage(const logfault::Message& msg) override {
            switch(msg.level_) {
                case LogLevel::ERROR:
                    qWarning() << "[Error] "<< msg.msg_;
                    break;
                case LogLevel::WARN:
                    qWarning() << msg.msg_;
                    break;
                case LogLevel::INFO:
                case LogLevel::NOTICE:
                    qInfo() << msg.msg_;
                    break;
                case LogLevel::DEBUGGING:
                case LogLevel::TRACE:
                    qDebug() << msg.msg_;
                    break;
                default:
                    ; // Nothing
            }
        }
    };
#endif

#if defined(LOGFAULT_USE_COCOA_NLOG) || defined(LOGFAULT_USE_COCOA_NLOG_IMPL)
    class CocoaHandler : public Handler {
    public:
        CocoaHandler(LogLevel level)
        : Handler(level) {}

        void LogMessage(const logfault::Message& msg) override;
    };

    // Must be defined once, when included to a .mm file
    #ifdef LOGFAULT_USE_COCOA_NLOG_IMPL
        void CocoaHandler::LogMessage(const logfault::Message& msg) {
            const std::string text = LevelName(msg.level_) + " " + msg.msg_;
            NSLog(@"%s", text.c_str());
        }
    #endif //LOGFAULT_USE_COCOA_NLOG_IMPL
#endif // LOGFAULT_USE_COCOA_NLOG

#ifdef LOGFAULT_USE_WINDOWS_EVENTLOG
        class WindowsEventLogHandler : public Handler {
        public:
            WindowsEventLogHandler(const std::string& name, LogLevel level)
                : Handler(level) {
                h_ = RegisterEventSource(0, name.c_str());
            }

            ~WindowsEventLogHandler() {
                DeregisterEventSource(h_);
            }

            void LogMessage(const logfault::Message& msg) override {
                if (!h_) {
                    return;
                }
                WORD wtype = EVENTLOG_SUCCESS;
                switch (msg.level_) {
                case LogLevel::ERROR:
                    wtype = EVENTLOG_ERROR_TYPE;
                    break;
                case LogLevel::WARN:
                    wtype = EVENTLOG_WARNING_TYPE;
                    break;
                default:
                    ;
                }

                LPCSTR buffer = reinterpret_cast<LPCSTR>(msg.msg_.c_str());
                ReportEventA(h_, wtype, 0, 0, 0, 1, 0, &buffer, 0);
            }
        private:
            HANDLE h_ = {};
    };
#endif // LOGFAULT_USE_WINDOWS_EVENTLOG

    class LogManager {
        LogManager() = default;
        LogManager(const LogManager&) = delete;
        LogManager(LogManager &&) = delete;
        void operator = (const LogManager&) = delete;
        void operator = (LogManager&&) = delete;
    public:

        static LogManager& Instance() {
            static LogManager instance;
            return instance;
        }

        void LogMessage(Message message) {
            std::lock_guard<std::mutex> lock{mutex_};
            for(const auto& h : handlers_) {
                if (h->level_ >= message.level_) {
                    h->LogMessage(message);
                }
            }
        }

        void AddHandler(Handler::ptr_t && handler) {
            std::lock_guard<std::mutex> lock{mutex_};

            // Make sure we log at the most detailed level used
            if (level_ < handler->level_) {
                level_ = handler->level_;
            }
            handlers_.push_back(std::move(handler));
        }

        /*! Set handler.
         *
         * Remove any existing handlers.
         */
        void SetHandler(Handler::ptr_t && handler) {
            std::lock_guard<std::mutex> lock{mutex_};
            handlers_.clear();
            level_ = handler->level_;
            handlers_.push_back(std::move(handler));
        }
        
         /*! Remove all existing handlers
          * 
          */
        void ClearHandlers() {
            std::lock_guard<std::mutex> lock{mutex_};
            handlers_.clear();
            level_ = LogLevel::DISABLED;
        }


        void SetLevel(LogLevel level) {
            level_ = level;
        }

        LogLevel GetLoglevel() const noexcept {
            return level_;
        }

        bool IsRelevant(const LogLevel level) const noexcept {
            return !handlers_.empty() && (level <= level_);
        }

    private:
        std::vector<Handler::ptr_t> handlers_;
        std::mutex mutex_;
        LogLevel level_ = LogLevel::ERROR;
    };

#if __cplusplus >= 202002L
    template <typename... Args>
    class Log {
        std::tuple<Args ...> args_;
    public:
        Log(const LogLevel level, const char *file, const int line, const char *func, Args&&... args)
            : args_{std::forward<Args>(args)...}, level_{level}, file_{file}, line_{line}, func_{func} {}

        ~Log() {
            if constexpr (sizeof...(Args) == 0) {
                LogManager::Instance().LogMessage({out_.str(), level_, file_, line_, func_});
                return;
            }

            constexpr std::size_t num_args = sizeof...(Args);

            if constexpr (num_args ==  0) {
                LogManager::Instance().LogMessage({out_.str(), level_, file_, line_, func_});
                return;
            } else {
                auto log_fn = [&](bool wantJson) -> Extra {
                    std::array<std::string, num_args> strings;
                    std::array<bool, num_args> is_json{};
                    std::ostringstream extra_json;
                    std::ostringstream extra_content;
                    bool has_extra_json = false;
                    std::apply([&](auto&&... args) {
                        int n = 0;
                        (((std::tie(is_json[n], strings[n]) = toLog(args, wantJson)), ++n), ...);
                    }, args_);


                    for(auto i = 0u; i < num_args; ++i) {
                        if (is_json[i]) {
                            if (has_extra_json) {
                                extra_json << ',';
                            } else {
                                has_extra_json = true;
                            }
                            extra_json << strings[i];
                        } else {
                            extra_content << ' ' << strings[i];
                        }
                    }

                    return {extra_content.str(), extra_json.str()};
                };

                LogManager::Instance().LogMessage({out_.str(), level_, file_, line_, func_, log_fn});
            }
        }
#else
    class Log {
        public:
        Log(const LogLevel level, const char *file, const int line, const char *func)
            : level_{level}, file_{file}, line_{line}, func_{func} {}
        ~Log() {
            Message message(out_.str(), level_, file_, line_, func_);
            LogManager::Instance().LogMessage(message);
        }

#endif
        Log(const LogLevel level) : level_{level} {}
        std::ostringstream& Line() { return out_; }

private:
        const LogLevel level_;
        const char *file_{};
        const int line_{};
        const char *func_{};
        std::ostringstream out_;
    };

#if __cplusplus >= 202002L
    template<typename... U>
    Log(LogLevel       /*level*/,
        const char*    /*file*/,
        int            /*line*/,
        const char*    /*func*/,
        U&&...         /*args*/)
        -> Log<U...>;
#endif

} // namespace

// stream operators for QT to make common datatypes simple to log
#ifdef QBYTEARRAY_H
inline std::ostream& operator << (std::ostream& out, const QByteArray& v) {
    return out << v.constData();
}
#endif

#ifdef QSTRING_H
inline std::ostream& operator << (std::ostream& out, const QString& v) {
    return out << v.toUtf8().constData();
}
#endif

#ifdef QHOSTADDRESS_H
inline std::ostream& operator << (std::ostream& out, const QHostAddress& v) {
   return out << v.toString().toUtf8().constData();
}
#endif




#endif // _LOGFAULT_H


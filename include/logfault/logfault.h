#pragma once

/*
MIT License

Copyright (c) 2018 Jarle Aase

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
#include <functional>
#include <iomanip>
#include <memory>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#ifdef LOGFAULT_USE_SYSLOG
#   include <syslog.h>
#endif

#ifdef LOGFAULT_USE_ANDROID_NDK_LOG
#   include <android/log.h>
#endif

#define LOGFAULT_LOG(level) \
    ::logfault::LogManager::Instance().IsRelevant(level) && \
    ::logfault::Log(level).Line()

#define LFLOG_ERROR LOGFAULT_LOG(logfault::LogLevel::ERROR)
#define LFLOG_WARN LOGFAULT_LOG(logfault::LogLevel::WARN)
#define LFLOG_NOTICE LOGFAULT_LOG(logfault::LogLevel::NOTICE)
#define LFLOG_INFO LOGFAULT_LOG(logfault::LogLevel::INFO)
#define LFLOG_DEBUG LOGFAULT_LOG(logfault::LogLevel::DEBUG)
#define LFLOG_TRACE LOGFAULT_LOG(logfault::LogLevel::TRACE)

#ifdef LOGFAULT_ENABLE_ALL
#   define LFLOG_IFALL_ERROR(msg) LOGFAULT_LOG(logfault::LogLevel::ERROR) << msg
#   define LFLOG_IFALL_WARN(msg) LOGFAULT_LOG(logfault::LogLevel::WARN) << msg
#   define LFLOG_IFALL_NOTICE(msg) LOGFAULT_LOG(logfault::LogLevel::NOTICE) << msg
#   define LFLOG_IFALL_INFO(msg) LOGFAULT_LOG(logfault::LogLevel::INFO) << msg
#   define LFLOG_IFALL_DEBUG(msg) LOGFAULT_LOG(logfault::LogLevel::DEBUG) << msg
#   define LFLOG_IFALL_TRACE(msg) LOGFAULT_LOG(logfault::LogLevel::TRACE) << msg
# else
#   define LFLOG_IFALL_ERROR(msg)
#   define LFLOG_IFALL_WARN(msg)
#   define LFLOG_IFALL_NOTICE(msg)
#   define LFLOG_IFALL_INFO(msg)
#   define LFLOG_IFALL_DEBUG(msg)
#   define LFLOG_IFALL_TRACE(msg)
#endif

namespace logfault {

    enum class LogLevel { ERROR, WARN, INFO, NOTICE, DEBUG, TRACE };

    struct Message {
        Message(const std::string && msg, const LogLevel level)
        : msg_{std::move(msg)}, level_{level} {}

        const std::string msg_;
        const std::chrono::system_clock::time_point when_ = std::chrono::system_clock::now();
        const LogLevel level_;
    };

    class Handler {
    public:
        Handler(LogLevel level = LogLevel::INFO) : level_{level} {}
        virtual ~Handler() = default;
        using ptr_t = std::unique_ptr<Handler>;

        virtual void LogMessage(const Message& msg) = 0;
        const LogLevel level_;

        static const std::string& LevelName(const LogLevel level) {
            static const std::array<std::string, 6> names =
                {{"ERROR", "WARNING", "NOTICE", "INFO", "DEBUG", "TRACE"}};
            return names.at(static_cast<size_t>(level));
        }
    };

    class StreamHandler : public Handler {
    public:
        StreamHandler(std::ostream& out, LogLevel level) : Handler(level), out_{out} {}

        void LogMessage(const logfault::Message& msg) override {

            const auto tt = std::chrono::system_clock::to_time_t(msg.when_);
            const auto tm = std::localtime(&tt);

            out_ << std::put_time(tm, "%c %Z") << ' ' << LevelName(msg.level_)
                << ' ' << std::this_thread::get_id()
                << ' ' << msg.msg_ << std::endl;
        }

    private:
        std::ostream& out_;
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

        SyslogHandler(LogLevel level, int facility = LOG_USER)
        : Handler(level), facility_{facility} {}

        void LogMessage(const logfault::Message& msg) override {
            static const std::array<int, 6> syslog_priority =
                { LOG_ERR, LOG_WARNING, LOG_NOTICE, LOG_INFO, LOG_DEBUG, LOG_DEBUG };
            static std::once_flag syslog_opened;
            std::call_once(syslog_opened, [] {
                openlog(nullptr, 0, facility_);
            });

            syslog(syslog_priority.at(static_cast<int>(level_)), "%s", msg.c_str());
        }

    private:
        int facility_;
    }
#endif

#ifdef LOGFAULT_USE_ANDROID_NDK_LOG

    class AndroidHandler : public Handler {
    public:
        AndroidHandler(const std::string& name, LogLevel level)
        : Handler(level), name_{name} {}

        void Handler::LogMessage(const logfault::Message& msg) override {
            static const std::array<int, 6> android_priority =
                { ANDROID_LOG_ERROR, ANDROID_LOG_WARN, ANDROID_LOG_INFO,
                  ANDROID_LOG_INFO, ANDROID_LOG_DEBUG, ANDROID_LOG_VERBOSE };
            __android_log_write(android_priority.at(static_cast<int>(level_)),
                                name_.c_str(), msg.c_str());
        }

    private:
        const std::char name_;
    };
#endif

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
        std::mutex mutex_;
        std::vector<Handler::ptr_t> handlers_;
        LogLevel level_ = LogLevel::ERROR;
    };

    class Log {
    public:
        Log(const LogLevel level) : level_{level} {}
        ~Log() {
            Message message(out_.str(), level_);
            LogManager::Instance().LogMessage(message);
        }

        std::ostringstream& Line() { return out_; }

private:
        const LogLevel level_;
        std::ostringstream out_;
    };
} // namespace

#endif // _LOGFAULT_H


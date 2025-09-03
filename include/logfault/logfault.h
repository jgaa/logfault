#pragma once
/*
MIT License

Copyright (c) 2018 - 2025 Jarle Aase

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

#include <algorithm>
#include <array>
#include <assert.h>
#include <chrono>
#include <cstring>
#include <fstream>
#include <functional>
#include <iomanip>
#include <memory>
#include <mutex>
#include <sstream>
#include <streambuf>
#include <string>
#include <thread>
#include <type_traits>
#include <vector>

// If you have a custom handler and don't want to update your code yet to use
// the new noexcept handler interface, you can define this to 0.
// However, make sure you don't mix noexcept and non-noexcept handlers in the same
// application
#if !defined(LOGFAULT_USE_NOEXCEPT)
#   define LOGFAULT_USE_NOEXCEPT 1
#endif

#if LOGFAULT_USE_NOEXCEPT
#   define LOGFAULT_NOEXCEPT noexcept
#else
#   define LOGFAULT_NOEXCEPT
#endif

#ifdef _WIN32
#    include <io.h>         // _write
#    include <BaseTsd.h>    // SSIZE_T
using ssize_t = SSIZE_T;
#    define _logfault_posix_write _write
#else
#    include <unistd.h>     // write
#    include <cerrno>       // errno
#    include <string.h>     // strerror
#    define _logfault_posix_write write
#endif

#if __cplusplus >= 202002L
#   include <optional>
#   include <span>
#endif

#if __cplusplus >= 201703L
#   include <string_view>
#endif

#ifndef LOGFAULT_USE_UTCZONE
#   define LOGFAULT_USE_UTCZONE 0
#endif

#ifndef LOGFAULT_USE_MUTEX
#   define LOGFAULT_USE_MUTEX 1
#endif

#if LOGFAULT_USE_MUTEX
#    define LOGFAULT_LOCK_GUARD std::lock_guard<std::mutex> lock{mutex_};
#else
#    define LOGFAULT_LOCK_GUARD
#endif

#ifndef LOGFAULT_TIME_FORMAT
//#   define LOGFAULT_TIME_FORMAT "%Y-%m-%d %H:%M:%S."
#endif

#ifndef LOGFAULT_TIME_PRINT_MILLISECONDS
#   define LOGFAULT_TIME_PRINT_MILLISECONDS 1
#endif

#ifndef LOGFAULT_TIME_PRINT_TIMEZONE
#   define LOGFAULT_TIME_PRINT_TIMEZONE 1
#endif

// You can set this this '\n' to impove the performance a little.
// For small output streams, the performance difference is negligible.
// and it will not flush the output stream automatically.
#ifndef LOGFAULT_ENDL
#   define LOGFAULT_ENDL std::endl
#endif

#ifdef LOGFAULT_WITH_SYSTEMD
#   include <sys/uio.h>
#   include <dlfcn.h>
#   include <unistd.h>
#   include <sys/syscall.h>
#endif

#if defined(LOGFAULT_USE_SYSLOG) || defined(LOGFAULT_WITH_SYSTEMD)
#   include <syslog.h>
#endif

#ifdef LOGFAULT_WITH_OS_LOG
#   include <os/log.h>
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
        inline const char *logfault_get_thread_name_() LOGFAULT_NOEXCEPT {
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

#ifndef LOGFAULT_SB_BUFFER_SIZE
#   define LOGFAULT_SB_BUFFER_SIZE 128u * 2 // 256 bytes
#endif

namespace logfault {

    enum class LogLevel { DISABLED, ERROR, WARN, NOTICE, INFO, DEBUGGING, TRACE };

#if __cplusplus >= 202002L
namespace sb {

constexpr auto buffer_size = LOGFAULT_SB_BUFFER_SIZE;
constexpr auto static_buffers = 2;
using buffer_type = std::array<char, buffer_size>;
//using pair_type   = std::pair<const char*, std::size_t>;
using buffers_type = std::span<buffer_type*>;
using write_t = std::function<void(const buffers_type&, size_t totalBytes)>;
}

class fast_streambuf : public std::streambuf {

public:

    explicit fast_streambuf(sb::write_t write_func) noexcept //(std::is_nothrow_move_constructible<sb::write_t>::value)
        : write_func_(std::move(write_func)) {
        allocate_buffer();
    }

    ~fast_streambuf() override {
        sync();
    }

    void reuse() {
        sync();
        allocate_buffer();
    }

    inline int sync() noexcept override {
        flush_buffers();
        return 0;
    }

    void clear() {
        clear_heap_buffers();
    }

    size_t size() const noexcept {
        switch(buffers_.index()) {
            case BuffeKind::ARRAY:
                return std::get<BuffeKind::ARRAY>(buffers_).size() * sb::buffer_size + (pptr() - pbase());
            case BuffeKind::VECTOR:
                return std::get<BuffeKind::VECTOR>(buffers_).size() * sb::buffer_size + (pptr() - pbase());
            default:
                return 0;
        }
    }

    std::string str() {
        std::string result;
        if (buffers_.index() == BuffeKind::ARRAY) [[likely]] {
            auto& array_buffers = std::get<BuffeKind::ARRAY>(buffers_);
            assert(array_buffers.size() > buffer_count_);

            sb::buffers_type buffer_span(array_buffers.data(), buffer_count_);
            const size_t last_buffer_size = static_cast<std::size_t>(pptr() - array_buffers[buffer_count_ -1]->data());
            size_t totalBytes = (buffer_count_ -1) * sb::buffer_size + last_buffer_size;

            result.reserve(totalBytes);
            for (const auto& b : buffer_span) {
                auto bytes = std::min(b->size(), totalBytes);
                result.append(b->data(), bytes);
                totalBytes -= bytes;
            }
        } else if (buffers_.index() == BuffeKind::VECTOR) {
            auto& vector_buffers = std::get<BuffeKind::VECTOR>(buffers_);
            assert(vector_buffers.size() >= buffer_count_);

            sb::buffers_type buffer_span(vector_buffers.data(), buffer_count_);
            const size_t last_buffer_size = static_cast<std::size_t>(pptr() - vector_buffers[buffer_count_ -1]->data());
            size_t totalBytes = (buffer_count_ -1) * sb::buffer_size + last_buffer_size;

            result.reserve(totalBytes);
            for (const auto& b : buffer_span) {
                auto bytes = std::min(b->size(), totalBytes);
                result.append(b->data(), bytes);
                totalBytes -= bytes;
            }
        }
        clear();
        return result;
    }

protected:
    inline int_type overflow(int_type ch) noexcept override {
        if (bad_) [[unlikely]] {
            return traits_type::eof();
        }
        assert(buffers_.index() != BuffeKind::NONE && "No buffers allocated for streambuf");
        if (traits_type::eq_int_type(ch, traits_type::eof())) {
            return traits_type::not_eof(ch);
        }
        char c = traits_type::to_char_type(ch);
        char* p = pptr(); char* e = epptr();
        if (p == e) {
            allocate_buffer();
            p = pptr();
        }
        *p = c;
        pbump(1);
        return ch;
    }

    inline std::streamsize xsputn(const char* s, std::streamsize count) override {
        std::streamsize written = 0;
        while (written < count) {
            if (bad_) [[unlikely]] {
                return written;
            }
            assert(buffers_.index() != BuffeKind::NONE && "No buffers allocated for streambuf");
            char* p = pptr(); char* e = epptr();
            std::size_t space = static_cast<std::size_t>(e - p);
            if (space == 0) {
                allocate_buffer();
                p = pptr(); e = epptr();
                space = static_cast<std::size_t>(e - p);
            }
            std::size_t to_write = std::min(space, static_cast<std::size_t>(count - written));
            std::memcpy(p, s + written, to_write);
            pbump(static_cast<int>(to_write));
            written += to_write;
        }
        return written;
    }

private:
    inline void allocate_buffer() noexcept {
        if (buffer_count_ == 0) {
            // first inline buffer
            buffers_.emplace<BuffeKind::ARRAY>();
            auto& a = std::get<BuffeKind::ARRAY>(buffers_);
            a[0] = &inline_buffer_;
            auto * b = a[0];
            setp(b->data(), b->data() + sb::buffer_size);
        } else if (buffer_count_ < sb::static_buffers) {
            auto& a = std::get<BuffeKind::ARRAY>(buffers_);
            try {
                a[buffer_count_] = new sb::buffer_type;
            } catch (const std::bad_alloc&) {
                bad_ = true;
                return;
            }
            auto * b = a[buffer_count_];
            setp(b->data(), b->data() + sb::buffer_size);
        } else if (buffer_count_ == sb::static_buffers) {
            // Switch to vector buffers
            try {
                std::vector<sb::buffer_type *> vb;
                vb.reserve(sb::static_buffers + 16);
                auto& a = std::get<BuffeKind::ARRAY>(buffers_);
                vb.insert(vb.end(), a.data(), a.data() + sb::static_buffers);
                buffers_.emplace<BuffeKind::VECTOR>(std::move(vb));
                goto expand_vector;
            } catch (const std::bad_alloc&) {
                bad_ = true;
                return;
            }
        } else {
expand_vector:
            // We have more than static_buffers, so we need to allocate a new buffer
            auto& vector_buffers = std::get<BuffeKind::VECTOR>(buffers_);
            try {
                vector_buffers.emplace_back(new sb::buffer_type);
            } catch (const std::bad_alloc&) {
                bad_ = true;
                return;
            }
            setp(vector_buffers.back()->data(), vector_buffers.back()->data() + sb::buffer_size);
        }
        ++buffer_count_;
    }

    inline void flush_buffers() noexcept {
        if (buffers_.index() == BuffeKind::ARRAY) [[likely]] {
            auto& array_buffers = std::get<BuffeKind::ARRAY>(buffers_);
            assert(array_buffers.size() > buffer_count_);

            sb::buffers_type buffer_span(array_buffers.data(), buffer_count_);
            const size_t last_buffer_size = static_cast<std::size_t>(pptr() - array_buffers[buffer_count_ -1]->data());
            const size_t totalBytes = (buffer_count_ -1) * sb::buffer_size + last_buffer_size;
            write_func_(buffer_span, totalBytes);

        } else if (buffers_.index() == BuffeKind::VECTOR) {
            auto& vector_buffers = std::get<BuffeKind::VECTOR>(buffers_);
            assert(vector_buffers.size() >= buffer_count_);

            const size_t last_buffer_size = static_cast<std::size_t>(pptr() - vector_buffers[buffer_count_ -1]->data());
            const size_t totalBytes = (buffer_count_ -1) * sb::buffer_size + last_buffer_size;

            sb::buffers_type buffer_span(vector_buffers.data(), buffer_count_);
            write_func_(buffer_span, totalBytes);
        }

        clear_heap_buffers();
    }

    inline void clear_heap_buffers() noexcept {
        if (buffers_.index() == BuffeKind::ARRAY) [[likely]] {
            auto& array_buffers = std::get<BuffeKind::ARRAY>(buffers_);
            for (auto i = 1ul ; i < buffer_count_; ++i) {
                assert(array_buffers[i]);
                assert(i < array_buffers.size());
                delete array_buffers[i];
                array_buffers[i] = nullptr;
            }
        } else if (buffers_.index() == BuffeKind::VECTOR) {
            auto& vector_buffers = std::get<BuffeKind::VECTOR>(buffers_);
            for (auto i = 1ul ; i < buffer_count_; ++i) {
                assert(i < vector_buffers.size());
                assert(vector_buffers[i]);
                delete vector_buffers[i];
            }
            vector_buffers.clear();
        }

        buffer_count_ = 0;
        buffers_ = std::monostate{};
    }

    enum BuffeKind {
        NONE,
        ARRAY,
        VECTOR
    };

    bool bad_{false};
    sb::buffer_type inline_buffer_;
    std::variant<std::monostate,
                 std::array<sb::buffer_type *, sb::static_buffers>,
                 std::vector<sb::buffer_type *>> buffers_{std::monostate{}};

    std::size_t buffer_count_{0};
    sb::write_t write_func_;
};
#endif // C++20

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

#if __cplusplus >= 202002L
    struct Extra {
        std::string content;
        std::string json;
    };
#else
    struct Extra {};
#endif

    template <typename T>
    void JsonEscape(const T& msg, std::ostream& out) {
        static constexpr std::array<char, 16> hex = {'0','1','2','3','4','5','6','7','8','9','A','B','C','D','E','F'};
        static constexpr std::array<char, 93> table = {
            1, 1, 1, 1, 1, 1, 1, 1, 'b', 't', 'n', 1, 'f', 'r', 1, 1, 1
            , 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0
            , 0, '"', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
            , 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
            , 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
            , 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, '\\'};

        // Scan for first non-printable character
        size_t len = 0;
        const char *msg_end = msg.data() + msg.size();
        {
            for (const auto *p = msg.data(); p < msg_end; ++p) {
                const auto uc = static_cast<unsigned char>(*p);
                if (uc < table.size() && table[uc] != 0) {
                    break;
                }
                ++len;
            }
        }

        if (len) {
            out.write(msg.data(), len);
        }
        const auto len_after_escape = msg.size() - len;
        if (!len_after_escape) [[likely]] {
            // No need to escape, just write the string as is
            return;
        }

        const char *from = msg.data() + len;
        const char *p = from;
        
        std::array<char, 48> buffer;
        char *pp = buffer.data();
        const char *buf_end = pp + buffer.size();

        auto flush_buffer = [&]() {
            if (pp > buffer.data()) {
                out.write(buffer.data(), pp - buffer.data());
                pp = buffer.data();
            }
        };

        auto putc_buffer = [&](char c) {
            if (pp >= buf_end) [[unlikely]] {
                flush_buffer();
            }
            *pp = c;
            ++pp;
        };

        for (; p < msg_end; ++p) {
            const auto uc = static_cast<unsigned char>(*p);
            if (uc >= table.size()) {
                // This is a printable character, just write it
                putc_buffer(*p);
                continue;
            }

            assert(uc < table.size());
            const auto tc = table[uc];
            if (tc == 0) [[likely]] {
                putc_buffer(*p);
                continue;
            }
            if (tc != 1) {
                putc_buffer('\\');
                putc_buffer(tc);
                continue;
            }

            assert(uc < 0x20);
            // control characters as \u00XX
            putc_buffer('\\'); putc_buffer('u');
            putc_buffer('0');  putc_buffer('0');
            putc_buffer(hex[(uc >> 4) & 0xF]);
            putc_buffer(hex[ uc       & 0xF]);
        }

        flush_buffer();
    }

    struct Message {
#if __cplusplus >= 202002L
        using extras_t = std::function<Extra(bool wantJson)>;
#endif
        Message(const std::string& msg, const LogLevel level, const char *file = nullptr
                , const int line = 0, const char *func = nullptr
#if __cplusplus >= 202002L
                , const extras_t& log_fn = nullptr
#endif
            ) LOGFAULT_NOEXCEPT
            : msg_{msg}, level_{level}, file_{file}, line_{line}, func_{func}
#if __cplusplus >= 202002L
            , log_fn_{log_fn}
#endif
        {
#ifdef _WIN32
            static std::once_flag once;
            std::call_once(once, [] {
                _tzset();
            });
#endif
        }

        const std::string& msg_;
        const std::chrono::system_clock::time_point when_ = std::chrono::system_clock::now();
        const LogLevel level_;
        const char *file_{};
        const int line_{};
        const char *func_{};
#if __cplusplus >= 202002L
        const extras_t& log_fn_ {};
#endif
        const std::string thread_{ThreadNameToString(LOGFAULT_THREAD_NAME)};
    };

    inline void PrintTimestamp(const struct tm *tm, int ms, std::ostream& out) LOGFAULT_NOEXCEPT {
        assert(tm != nullptr);
#if defined(LOGFAULT_TIME_FORMAT)
        out << std::put_time(tm, LOGFAULT_TIME_FORMAT);
#else
#   if LOGFAULT_TIME_PRINT_TIMEZONE
#       if LOGFAULT_USE_UTCZONE
            const char *zone = "UTC";
#       else
#           if defined(_WIN32)
                const char* zone = _tzname[(tm->tm_isdst > 0) ? 1 : 0];
                if (!zone) zone = "";
#           else
                const char *zone = tm->tm_zone;
#           endif // _WIN32
#       endif // LOGFAULT_USE_UTCZONE
#   else // LOGFAULT_TIME_PRINT_TIMEZONE
        const char *zone = "";
#   endif // LOGFAULT_TIME_PRINT_TIMEZONE
        std::array<char, 48> buffer;
        const int len = std::snprintf(buffer.data(), buffer.size(),
                                "%04d-%02d-%02d %02d:%02d:%02d.%03d %s",
                                tm->tm_year+1900, tm->tm_mon+1, tm->tm_mday,
                                tm->tm_hour, tm->tm_min, tm->tm_sec,
                                ms, zone);
        if (len > 0) {
            out.write(buffer.data(), len);
        }
#endif // LOGFAULT_TIME_FORMAT
    }

    class Handler {
    public:
        Handler(LogLevel level = LogLevel::INFO)
            : level_{level} {}

        Handler(std::string name, LogLevel level = LogLevel::INFO)
            : level_{level}, name_{std::move(name)} {}
        virtual ~Handler() = default;
        using ptr_t = std::unique_ptr<Handler>;

        virtual void LogMessage(const Message& msg) LOGFAULT_NOEXCEPT = 0;
        const LogLevel level_;
        const std::string name_;

// check if c++20 or later
#if __cplusplus >= 201703L
        static std::string_view LevelName(const LogLevel level) LOGFAULT_NOEXCEPT {
            static constexpr std::array<std::string_view, 7> names =
                {{"DISABLED", "ERROR", "WARNING", "NOTICE", "INFO", "DEBUG", "TRACE"}};
            assert(static_cast<size_t>(level) < names.size() && "LogLevel out of range");
            return names[static_cast<size_t>(level)];
        }
#else
        static const char * LevelName(const LogLevel level) {
            static const std::array<const char *, 7> names =
                {{"DISABLED", "ERROR", "WARNING", "NOTICE", "INFO", "DEBUG", "TRACE"}};
            assert(static_cast<size_t>(level) < names.size() && "LogLevel out of range");
            return names[static_cast<size_t>(level)];
        }
#endif

        static void PrintTime(std::ostream& out, const logfault::Message& msg) LOGFAULT_NOEXCEPT {
            auto tt = std::chrono::system_clock::to_time_t(msg.when_);
            auto when_rounded = std::chrono::system_clock::from_time_t(tt);
            if (when_rounded > msg.when_) {
                --tt;
                when_rounded -= std::chrono::seconds(1);
            }

            if (const auto tm = (LOGFAULT_USE_UTCZONE ? std::gmtime(&tt) : std::localtime(&tt))) {
                const int ms = std::chrono::duration_cast<std::chrono::duration<int, std::milli>>(msg.when_ - when_rounded).count();

                PrintTimestamp(tm, ms, out);
            } else {
                out << "0000-00-00 00:00:00.000";
            }

        }

        static void PrintMessage(std::ostream& out, const logfault::Message& msg) LOGFAULT_NOEXCEPT {
            PrintTime(out, msg);

            out << ' ' << LevelName(msg.level_)
                << ' ' << LOGFAULT_THREAD_NAME;

            if (msg.func_) {
                out << " {" << msg.func_ << '}';
            }
#if __cplusplus >= 202002L
            if (msg.log_fn_) {
                Extra extra = msg.log_fn_(false);
                out << ' ' << extra.content;
            }
#endif

            out  << ' ' << msg.msg_;
        }

        static const char *ShortenPath(const char *path) LOGFAULT_NOEXCEPT {
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

        void LogMessage(const Message& msg) LOGFAULT_NOEXCEPT override {
            PrintMessage(out_, msg);
            out_ << LOGFAULT_ENDL;
        }

    private:
        std::unique_ptr<std::ostream> file_;
        std::ostream& out_;
    };

#if __cplusplus >= 202002L
    class StreamBufferHandler : public Handler {
    public:
        StreamBufferHandler(int fd, LogLevel level)
            : Handler(level), sb_{[fd](const sb::buffers_type& buffers, size_t bytes) -> void {
                for(const auto& b : buffers) {
                    bytes -= _logfault_posix_write(fd, b->data(), std::min(b->size(), bytes));
                }
            }} {}

        void LogMessage(const Message& msg) LOGFAULT_NOEXCEPT override {
            std::ostream os{ &sb_ };     // wrap the streambuf
            PrintMessage(os, msg);
            os << '\n';
            sb_.reuse();
        }

    private:
        fast_streambuf sb_;
    };

#endif

#ifdef LOGFAULT_ENABLE_POSIX_WRITE
    class FileIOHandler : public Handler {
    public:
        FileIOHandler(int out, LogLevel level) : Handler(level), out_{out} {}

        void LogMessage(const Message& msg) LOGFAULT_NOEXCEPT override {
            std::ostringstream buffer;
            PrintMessage(buffer, msg);
            buffer << '\n';
            const auto str = buffer.str();
            if (_logfault_posix_write(out_, str.data(), str.size()) != static_cast<ssize_t>(str.size())) {
                // Handle error, e.g., throw an exception or log an error
                std::cerr << "Logfault: Failed to write to file descriptor " << out_ << ": " << strerror(errno) << '\n';
            }
        }

    private:
        int out_;
    };
#endif

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

        void LogMessage(const Message& msg) LOGFAULT_NOEXCEPT override {
        // Use severity level names recognized by Grafana
#if __cplusplus >= 201703L
            static constexpr std::array<std::string_view, 7> names =
#else
            static const std::array<const char *, 7> names =
#endif
            {{"disabled", "error", "warn", "info", "info", "debug", "trace"}};

#if __cplusplus >= 201703L
            static constexpr std::array<std::string_view, 7> label_names =
#else
            static const std::array<const char *, 7> label_names =
#endif
            {{"time", "level", "thread", "src_file", "src_line", "func", "log"}};

#if __cplusplus >= 202002L
            std::optional<Extra> extra;

            if (msg.log_fn_) {
                extra = msg.log_fn_(true);
            }
#endif

            bool first = true;
            auto add_label = [&](Fields label) {
                const auto name = label_names[static_cast<size_t>(label)];
                if (first) [[unlikely]] {
                    first = false;
                } else {
                    out_ << ',';
                }
                out_ << '"' << name << "\":\"";
            };

            auto add = [&](Fields label,
#if __cplusplus >= 201703L
                            std::string_view value
#else
                            const char *value
#endif
                        ) {
                add_label(label);
#if __cplusplus < 201703L
                assert(value != nullptr);
#endif
                out_ << value;
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
                add_label(Fields::TIME);
                PrintTime(out_, msg);
                out_ << '"';
            }

            if (fields_ & (1 << Fields::LEVEL)) {
                add_label(Fields::LEVEL);
                assert(static_cast<unsigned int>(msg.level_) < names.size() && "LogLevel out of range");
                out_ << names[static_cast<unsigned int>(msg.level_)] << '"';
            }

            if (fields_ & (1 << Fields::THREAD)) {
                add_label(Fields::THREAD);
                out_ << LOGFAULT_THREAD_NAME << '"';
            }

            if (fields_ & (1 << Fields::FILE) && msg.file_) {
                add(Fields::FILE, ShortenPath(msg.file_));
            }

            if (fields_ & (1 << Fields::LINE) && msg.line_) {
                add_label(Fields::LINE);
                out_ << msg.line_ << '"';
            }

            if (fields_ & (1 << Fields::FUNC) && msg.func_) {
                add(Fields::FUNC, msg.func_);
            }

#if __cplusplus >= 202002L
            if (extra && !extra->json.empty()) {
                add_json(extra->json);
            }
#endif

            if (fields_ & (1 << Fields::MSG)) {
                add_label(Fields::MSG);
                JsonEscape(msg.msg_, out_);
#if __cplusplus >= 202002L
                if (extra && !extra->content.empty()) {
                    out_ << ' ' << extra->content;
                }
#endif
                out_ << '"';
            }

            out_ << '}' << LOGFAULT_ENDL;
        }

    private:
        std::unique_ptr<std::ofstream> file_;
        std::ostream& out_;
        const int fields_{};
    };

    class ProxyHandler : public Handler {
    public:
        using fn_t = std::function<void(const Message&)> ;

        ProxyHandler(const fn_t& fn, LogLevel level) : Handler(level), fn_{fn} {
            assert(fn_);
        }

        ProxyHandler(std::string name, const fn_t& fn, LogLevel level)
            : Handler(std::move(name), level), fn_{fn} {
            assert(fn_);
        }

        void LogMessage(const logfault::Message& msg) LOGFAULT_NOEXCEPT override {
            try {
                fn_(msg);
            } catch (const std::exception& e) {
                assert(false);
            }
        }

    private:
        const fn_t fn_;
    };

#ifdef LOGFAULT_WITH_OS_LOG
    // Apple os_log handler (macOS, iOS, tvOS, watchOS)
    class OsLogHandler : public Handler {
    public:
        struct Options {
            Options() {}
            Options(const std::string& subsystem, const std::string& category = "default")
                : subsystem{subsystem}, category{category} {}
            Options(const std::string& subsystem, const std::string& category, bool publicOutput)
                : subsystem{subsystem}, category{category}, public_output{publicOutput} {}
            std::string subsystem = "logfault"; // e.g. "com.example.app"
            std::string category  = "default";  // e.g. "network"
            bool        public_output =
#ifdef NDEBUG
                false; // Release: redact by default
#else
                true;  // Debug: show everything
#endif
        };

        explicit OsLogHandler(LogLevel level = LogLevel::INFO, Options opt = {})
            : Handler(level), logger_{os_log_create(opt.subsystem.c_str(), opt.category.c_str())}, opt_{opt} {}

        OsLogHandler(const std::string& name, LogLevel level = LogLevel::INFO, Options opt = {})
            : Handler(name, level), logger_{os_log_create(opt.subsystem.c_str(), opt.category.c_str())}, opt_{opt} {}

        ~OsLogHandler() override {
            if (logger_) {
                // os_log_t follows os_object semantics; release when done.
                os_release(logger_);
            }
        }

        void LogMessage(const Message& msg) LOGFAULT_NOEXCEPT override {
            if (!logger_) return;

            // Map logfault levels to os_log types
            const os_log_type_t t = map_type(msg.level_);

            // Reuse existing formatting so different backends look alike
            std::ostringstream out;
            PrintMessage(out, msg);
            const std::string s = out.str();

            if (opt_.public_output) {
                os_log_with_type(logger_, t, "%{public}s", s.c_str());
            } else {
                os_log_with_type(logger_, t, "%{private}s", s.c_str());
            }
        }

    private:
        static os_log_type_t map_type(LogLevel lvl) LOGFAULT_NOEXCEPT {
            switch (lvl) {
            case LogLevel::ERROR:     return OS_LOG_TYPE_ERROR;
            case LogLevel::WARN:      return OS_LOG_TYPE_DEFAULT; // could also be INFO; WARN maps best to DEFAULT
            case LogLevel::NOTICE:    return OS_LOG_TYPE_DEFAULT;
            case LogLevel::INFO:      return OS_LOG_TYPE_INFO;
            case LogLevel::DEBUGGING: return OS_LOG_TYPE_DEBUG;
            case LogLevel::TRACE:     return OS_LOG_TYPE_DEBUG;
            default:                  return OS_LOG_TYPE_DEFAULT;
            }
        }

        os_log_t logger_{};
        Options  opt_{};
    };
#endif // LOGFAULT_WITH_OS_LOG


#ifdef LOGFAULT_WITH_SYSTEMD
#if __cplusplus < 201703L
        static_assert(false, "SystemdHandler requires C++17 or newer");
#endif

    class SystemdHandler final : public Handler {
        static constexpr auto max_fields = 12u; // maximum number of fields we can send to journald
    public:
        using sd_journal_sendv_t = int (*)(const struct iovec *iov, int n);
        struct Options {
            Options() {};
            std::string_view ident{"logfault"}; // syslog identifier, defaults to "logfault"
        };

        explicit SystemdHandler(LogLevel level = LogLevel::INFO, const Options& opt = {})
            : Handler(level), opt_(opt) {
            init_backend();
        }

        explicit SystemdHandler(const std::string& name, LogLevel level = LogLevel::INFO, const Options& opt = {})
            : Handler(name, level), opt_(opt) {
            init_backend();
        }

        // For unit testing
        explicit SystemdHandler(sd_journal_sendv_t fn, const std::string& name, LogLevel level = LogLevel::INFO, const Options& opt = {})
            : Handler(name, level), opt_(opt), sd_journal_sendv_{fn} {
            assert(sd_journal_sendv_);
        }

        ~SystemdHandler() override {
        }

        void LogMessage(const Message& m) LOGFAULT_NOEXCEPT override {
                send_to_journald(m);
        }

    private:
        Options opt_;
        sd_journal_sendv_t sd_journal_sendv_{};

        static int map_priority(LogLevel lvl) {
            // journald/syslog priorities: 0=EMERG..7=DEBUG
            switch (lvl) {
            case LogLevel::ERROR:   return 3; // ERR
            case LogLevel::WARN: return 4; // WARNING
            case LogLevel::INFO:    return 6; // INFO
            case LogLevel::DEBUGGING:   return 7; // DEBUG
            case LogLevel::TRACE:   return 7; // DEBUG
            default:                return 5; // NOTICE
            }
        }

        void init_backend() {
            // Try to load libsystemd lazily
            void* h = dlopen("libsystemd.so.0", RTLD_LAZY | RTLD_LOCAL);
            if (!h) {
                const auto err = dlerror();
                const std::string err_str{err ? err : "Unknown error"};
                throw std::runtime_error{"Failed to load libsystemd: " + err_str};
            }
            sd_journal_sendv_ = reinterpret_cast<sd_journal_sendv_t>(
                dlsym(h, "sd_journal_sendv"));
            if (!sd_journal_sendv_) {
                auto err = dlerror();
                std::string err_str{err ? err : "Unknown error"};
                throw std::runtime_error{"Failed to find sd_journal_sendv in libsystemd: " + err_str};
            }
        }

        void send_to_journald(const Message& m) LOGFAULT_NOEXCEPT {
            // Build fields
            // TODO: Avoid individual strings as buffers
            std::array<std::string, max_fields> storage;
            std::array<iovec, max_fields> vec;
            auto num_fields = 0u;

            enum class Fields {
                MESSAGE, PRIORITY, CODE_FILE, CODE_FUNC, CODE_LINE,
                SYSLOG_IDENTIFIER, LOGGER, PID, THREAD_ID, TIMESTAMP,
                LOGFAULT_JSON
            };

            static constexpr std::array<std::string_view, 11> fields =
            {{"MESSAGE", "PRIORITY", "CODE_FILE", "CODE_FUNC", "CODE_LINE",
              "SYSLOG_IDENTIFIER", "LOGGER", "PID", "THREAD_ID", "TIMESTAMP",
              "LOGFAULT_JSON"}};

            auto push_field = [&](Fields f, std::string_view value) {
                if (num_fields < max_fields) {
                    if (value.empty()) return; // skip empty fields

                    auto& buffer = storage[num_fields];
                    assert(static_cast<unsigned>(f) < fields.size());
                    auto key = fields[static_cast<size_t>(f)];
                    buffer.reserve(key.size() + 1 + value.size());
                    buffer.append(key.data(), key.size());
                    buffer.push_back('=');
                    buffer.append(std::move(value));
                    vec[num_fields] = {const_cast<char*>(buffer.data()),
                                       static_cast<size_t>(buffer.size())};

                    ++num_fields;
                } else [[unlikely]] {
                    assert(false);
                    ; // Silently ignore the error. We can't throw here.
                }
            };

            // Required message and priority
            push_field(Fields::MESSAGE, to_text_message(m));
            push_field(Fields::PRIORITY, std::to_string(map_priority(m.level_)));

            // Standard code locations (journald recognizes these)
            if (m.file_)   push_field(Fields::CODE_FILE, m.file_);
            if (m.func_)   push_field(Fields::CODE_FUNC, m.func_);
            if (m.line_)   push_field(Fields::CODE_LINE, std::to_string(m.line_));

            // Identity
            if (!opt_.ident.empty()) push_field(Fields::SYSLOG_IDENTIFIER, opt_.ident);

            // Thread / process meta (optional)
            push_field(Fields::PID, std::to_string(::getpid()));
            push_field(Fields::THREAD_ID, std::to_string(__NR_gettid));

            // Timestamp (journald will timestamp on receive; including ISO can help searches)
            auto tt = std::chrono::system_clock::to_time_t(m.when_);
            auto when_rounded = std::chrono::system_clock::from_time_t(tt);
            if (when_rounded > m.when_) {
                --tt;
                when_rounded -= std::chrono::seconds(1);
            }
            if (const auto tm = (LOGFAULT_USE_UTCZONE ? std::gmtime(&tt) : std::localtime(&tt))) {
                const int ms = std::chrono::duration_cast<std::chrono::duration<int, std::milli>>(m.when_ - when_rounded).count();

#           if LOGFAULT_USE_UTCZONE
                const char *zone " UTC";
#           else
                const char *zone = tm->tm_zone;
#           endif

                std::array<char, 48> buffer;
                const int len = std::snprintf(buffer.data(), buffer.size(),
                                              "%04d-%02d-%02d %02d:%02d:%02d.%03d %s",
                                              tm->tm_year+1900, tm->tm_mon+1, tm->tm_mday,
                                              tm->tm_hour, tm->tm_min, tm->tm_sec,
                                              ms, zone);
                push_field(Fields::TIMESTAMP, std::string_view{buffer.data(), static_cast<std::size_t>(len)});
            }

            assert(sd_journal_sendv_);
            if (sd_journal_sendv_) {
                (void)sd_journal_sendv_(vec.data(), static_cast<int>(num_fields));
            }
        }

        // --- tiny helpers: adapt these to your Message type ---
        static std::string to_text_message(const Message& m) {
#if __cplusplus >= 202002L
            if (m.log_fn_) {
                Extra extra = m.log_fn_(false);
                std::string buf;
                buf.reserve(m.msg_.size() + 1 + extra.content.size());
                buf = m.msg_ + " " + extra.content;
                return buf;
            }
#endif

            return m.msg_;
        }
    };

#endif // LOGFAULT_WITH_SYSTEMD

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

        void LogMessage(const logfault::Message& msg) LOGFAULT_NOEXCEPT override {
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

        void LogMessage(const logfault::Message& msg) LOGFAULT_NOEXCEPT override {
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

        void LogMessage(const logfault::Message& msg) LOGFAULT_NOEXCEPT override {
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

        void LogMessage(const logfault::Message& msg) LOGFAULT_NOEXCEPT override;
    };

    // Must be defined once, when included to a .mm file
    #ifdef LOGFAULT_USE_COCOA_NLOG_IMPL
        void CocoaHandler::LogMessage(const logfault::Message& msg) LOGFAULT_NOEXCEPT {
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

            void LogMessage(const logfault::Message& msg) LOGFAULT_NOEXCEPT override {
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

        void LogMessage(Message message) LOGFAULT_NOEXCEPT {
            LOGFAULT_LOCK_GUARD
            for(const auto& h : handlers_) {
                if (h->level_ >= message.level_) {
                    h->LogMessage(message);
                }
            }
        }

        void AddHandler(Handler::ptr_t && handler) {
            LOGFAULT_LOCK_GUARD

            // Make sure we log at the most detailed level used
            if (level_ < handler->level_) {
                level_ = handler->level_;
            }
            handlers_.push_back(std::move(handler));
        }

        /*! Set handler.
         *
         * Remove any existing handlers and set a new one
         */
        void SetHandler(Handler::ptr_t && handler) {
            LOGFAULT_LOCK_GUARD
            handlers_.clear();
            level_ = handler->level_;
            handlers_.push_back(std::move(handler));
        }
        
         /*! Remove all existing handlers
          * 
          */
        void ClearHandlers() {
            LOGFAULT_LOCK_GUARD
            handlers_.clear();
            level_ = LogLevel::DISABLED;
        }

        /*! Remove a named handler
         *  @param name The name of the handler to remove
         */
        void RemoveHandler(const std::string& name) {
            if (name.empty()) {
                return; // Only named handlers can be removed
            }
            LOGFAULT_LOCK_GUARD
            handlers_.erase(std::remove_if(handlers_.begin(), handlers_.end(),
                [&](const Handler::ptr_t& h) { return h->name_ == name; }), handlers_.end());

            // If we removed the last handler, set the level to disabled
            if (handlers_.empty()) {
                level_ = LogLevel::DISABLED;
            }
        }

        void SetLevel(LogLevel level) {
            level_ = level;
        }

        LogLevel GetLoglevel() const LOGFAULT_NOEXCEPT {
            return level_;
        }

        bool IsRelevant(const LogLevel level) const LOGFAULT_NOEXCEPT {
            return (level <= level_);
        }

    private:
        std::vector<Handler::ptr_t> handlers_;
#if LOGFAULT_USE_MUTEX
        std::mutex mutex_;
#endif
        LogLevel level_ = LogLevel::DISABLED;
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
                const auto msg = out_.str();
                LogManager::Instance().LogMessage({msg, level_, file_, line_, func_});
                return;
            }

            constexpr std::size_t num_args = sizeof...(Args);

            if constexpr (num_args ==  0) {
                const auto msg = out_.str();
                LogManager::Instance().LogMessage({msg, level_, file_, line_, func_});
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
                const auto msg = out_.str();
                LogManager::Instance().LogMessage({msg, level_, file_, line_, func_, log_fn});
            }
        }
#else
    class Log {
        public:
        Log(const LogLevel level, const char *file, const int line, const char *func) LOGFAULT_NOEXCEPT
            : level_{level}, file_{file}, line_{line}, func_{func} {}
        ~Log() {
            const auto msg = out_.str();
            Message message(msg, level_, file_, line_, func_);
            LogManager::Instance().LogMessage(message);
        }

#endif
        Log(const LogLevel level) LOGFAULT_NOEXCEPT : level_{level} {}
        std::ostream& Line() { return out_; }

private:
        const LogLevel level_;
        const char *file_{};
        const int line_{};
        const char *func_{};
        std::ostringstream out_;
        //fast_streambuf sb_{{}};
        //std::ostream out_{&sb_};
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


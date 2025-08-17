
#include <iostream>
#include <string>
#include <chrono>


#define LOGFAULT_MIN_LOG_LEVEL DEBUGGING
#define SPDLOG_ACTIVE_LEVEL SPDLOG_LEVEL_DEBUG

//#define LOGFAULT_USE_MUTEX 0
#define LOGFAULT_ENABLE_POSIX_WRITE 1
#define LOGFAULT_ENDL '\n'


#include "logfault/logfault.h"

#include <boost/program_options.hpp>
#include <boost/uuid/uuid.hpp>
#include <boost/uuid/uuid_generators.hpp>

#include <boost/log/core.hpp>
#include <boost/log/trivial.hpp>
#include <boost/log/expressions.hpp>
#include <boost/log/utility/setup/common_attributes.hpp>
#include <boost/log/utility/setup/console.hpp>
#include <boost/log/utility/setup/file.hpp>
#include <boost/log/support/date_time.hpp>    // for format_date_time
#include <boost/log/sources/severity_logger.hpp>
#include <boost/log/sources/record_ostream.hpp>
#include <boost/log/attributes/named_scope.hpp>

#include <spdlog/spdlog.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/sinks/basic_file_sink.h>
#include <spdlog/pattern_formatter.h>


using namespace std;

struct Config {
    size_t num_log_entries{1000000};
    size_t debug_amplification{100}; // Amplification factor for debug logs
    size_t trace_amplification{200}; // Amplification factor for trace logs
    std::string level_console{"info"};
    std::string level_file{"info"};
    string file_name;
    bool as_json{false};
    string logger = "logfault";
};

logfault::LogLevel toLevel(std::string_view name) {
    if (name == "trace") return logfault::LogLevel::TRACE;
    if (name == "debug") return logfault::LogLevel::DEBUGGING;
    if (name == "info") return logfault::LogLevel::INFO;
    if (name == "warning") return logfault::LogLevel::WARN;
    if (name == "error") return logfault::LogLevel::ERROR;
    if (name == "none") return logfault::LogLevel::DISABLED;

    throw std::invalid_argument("Invalid log level: " + std::string(name));
}

boost::log::trivial::severity_level toBoostLevel(const std::string& lvl) {
    if (lvl == "trace")   return boost::log::trivial::trace;
    if (lvl == "debug")   return boost::log::trivial::debug;
    if (lvl == "info")    return boost::log::trivial::info;
    if (lvl == "warning") return boost::log::trivial::warning;
    if (lvl == "error")   return boost::log::trivial::error;
    throw std::invalid_argument("Invalid log level: " + lvl);
}

struct CustomData {
    string name;
    string email;
    uint64_t number{};
};

ostream& operator << (ostream& out, const CustomData& data) {
    out << "{Name: " << data.name << ", Email: " << data.email
        << ", Number: " << data.number << '}';
    return out;
};

void logWithLogfault(const Config& config) {
    // std::ios::sync_with_stdio(false);
    // std::cout.tie(nullptr);

    auto colsole_level = toLevel(config.level_console);
    auto file_level    = toLevel(config.level_file);
    if (colsole_level != logfault::LogLevel::DISABLED) {
        if (config.as_json) {
            logfault::LogManager::Instance().AddHandler(make_unique<logfault::JsonHandler>(cout, colsole_level));
        } else {
            logfault::LogManager::Instance().AddHandler(make_unique<logfault::StreamHandler>(cout, colsole_level));
            //logfault::LogManager::Instance().AddHandler(make_unique<logfault::FileIOHandler>(STDOUT_FILENO, colsole_level));
            //logfault::LogManager::Instance().AddHandler(make_unique<logfault::StreamBufferHandler>(STDOUT_FILENO, colsole_level));
        }
    }

    if (!config.file_name.empty() && file_level != logfault::LogLevel::DISABLED) {
        logfault::LogManager::Instance().AddHandler(make_unique<logfault::StreamHandler>(config.file_name, file_level, true));
    }

    for(auto i = 0u ; i < config.num_log_entries; ++i) {
        CustomData data{
            .name = "User" + std::to_string(i),
            .email = "user" + std::to_string(i) + "@example.com",
            .number = i * 123456
        };

        LFLOG_INFO << "Log entry #\"" << i << "\": " << data;
        //LFLOG_INFO << "Log entry #\"" << i;

        for (auto j = 0u; j < config.debug_amplification; ++j) {
            LFLOG_DEBUG << "Debugging log entry #" << i  << '/' << j << ": " << data;
        }

        for (auto j = 0u; j < config.trace_amplification; ++j) {
            LFLOG_TRACE << "Tracing log entry #" << i << '/' << j  << ": " << data << " with additional info";
        }
    }
}

void logWithBoostLog(const Config& config) {
    namespace logging   = boost::log;
    namespace sinks     = boost::log::sinks;
    namespace expr      = boost::log::expressions;
    namespace attrs     = boost::log::attributes;
    namespace src       = boost::log::sources;
    namespace keywords  = boost::log::keywords;


    // 1) Add common attributes (TimeStamp, ThreadID, etc.)
    logging::add_common_attributes();

    // 2) Console sink
    {
        auto sev_attr = expr::attr<boost::log::trivial::severity_level>("Severity");
        auto min_lvl  = toBoostLevel(config.level_console);

        if (config.as_json) {
            logging::add_console_log(
                std::cout,
                keywords::filter = sev_attr >= min_lvl,
                keywords::format = expr::stream
                                   << "{"
                                   << R"("timestamp":")"
                                   << expr::format_date_time<boost::posix_time::ptime>(
                                          "TimeStamp", "%Y-%m-%dT%H:%M:%S")
                                   << R"(",)"
                                   << R"("severity":")" << sev_attr << R"(",)"
                                   << R"("message":")" << expr::smessage << R"(")"
                                   << "}"
                );
        } else {
            logging::add_console_log(
                std::cout,
                keywords::filter = sev_attr >= min_lvl,
                keywords::format = expr::stream
                                   << "[" << expr::format_date_time<boost::posix_time::ptime>(
                                          "TimeStamp", "%H:%M:%S")
                                   << "] <" << sev_attr << "> " << expr::smessage
                );
        }
    }

    // 3) File sink (if requested)
    if (!config.file_name.empty()) {
        auto sev_attr = expr::attr<boost::log::trivial::severity_level>("Severity");
        auto min_lvl  = toBoostLevel(config.level_file);

        if (config.as_json) {
            logging::add_file_log(
                keywords::file_name = config.file_name,
                keywords::open_mode = std::ios::app,
                keywords::filter    = sev_attr >= min_lvl,
                keywords::format    = expr::stream
                                   << "{"
                                   << R"("timestamp":")"
                                   << expr::format_date_time<boost::posix_time::ptime>(
                                          "TimeStamp", "%Y-%m-%dT%H:%M:%S")
                                   << R"(",)"
                                   << R"("severity":")" << sev_attr << R"(",)"
                                   << R"("message":")" << expr::smessage << R"(")"
                                   << "}"
                );
        } else {
            logging::add_file_log(
                keywords::file_name = config.file_name,
                keywords::open_mode = std::ios::app,
                keywords::filter    = sev_attr >= min_lvl,
                keywords::format    = expr::stream
                                   << "[" << expr::format_date_time<boost::posix_time::ptime>(
                                          "TimeStamp", "%Y-%m-%d %H:%M:%S")
                                   << "] <" << sev_attr << "> " << expr::smessage
                );
        }
    }

    // 4) Your severity logger
    src::severity_logger<boost::log::trivial::severity_level> lg;

    // 5) Produce the same pattern of entries
    for (size_t i = 0; i < config.num_log_entries; ++i) {
        CustomData data{
            .name   = "User" + std::to_string(i),
            .email  = "user" + std::to_string(i) + "@example.com",
            .number = i * 123456
        };

        BOOST_LOG_SEV(lg, boost::log::trivial::info)
            << "Log entry #\"" << i << "\": " << data;

        for (size_t j = 0; j < config.debug_amplification; ++j) {
            BOOST_LOG_SEV(lg, boost::log::trivial::debug)
            << "Debugging log entry #" << i << '/' << j
            << ": " << data;
        }

        for (size_t j = 0; j < config.trace_amplification; ++j) {
            BOOST_LOG_SEV(lg, boost::log::trivial::trace)
            << "Tracing log entry #" << i << '/' << j
            << ": " << data << " with additional info";
        }
    }

    // 6) Flush all sinks (optional)
    logging::core::get()->flush();
}

void logWithSpdlog(const Config& config) {
    // 1) Parse levels
    auto console_level = spdlog::level::from_str(config.level_console);
    auto file_level    = spdlog::level::from_str(config.level_file);

    // 2) Create sinks
    std::vector<spdlog::sink_ptr> sinks;

    // Console sink (with or without JSON formatting)
    auto console_sink = std::make_shared<spdlog::sinks::stdout_color_sink_mt>();
    console_sink->set_level(console_level);
    if (config.as_json) {
        // Set a JSON-like pattern
        console_sink->set_formatter(
            std::make_unique<spdlog::pattern_formatter>(
                R"({"timestamp":"%+", "level":"%l", "msg":%v})"
                )
            );
    } else {
        // Default human-readable pattern
        console_sink->set_pattern("[%Y-%m-%dT%H:%M:%S.%e] [%^%l%$] %v");
    }
    sinks.push_back(console_sink);

    // File sink (if requested)
    if (!config.file_name.empty()) {
        auto file_sink = std::make_shared<spdlog::sinks::basic_file_sink_mt>(
            config.file_name, /*truncate=*/true
            );
        file_sink->set_level(file_level);
        if (config.as_json) {
            file_sink->set_formatter(
                std::make_unique<spdlog::pattern_formatter>(
                    R"({"timestamp":"%+", "level":"%l", "msg":%v})"
                    )
                );
        } else {
            file_sink->set_pattern("[%Y-%m-%dT%H:%M:%S.%e] [%l] %v");
        }
        sinks.push_back(file_sink);
    }

    // 3) Make & register a logger
    auto logger = std::make_shared<spdlog::logger>("perf_logger", begin(sinks), end(sinks));
    logger->set_level(std::min(console_level, file_level));
    spdlog::register_logger(logger);

    // 4) The same hot loop
    for (size_t i = 0; i < config.num_log_entries; ++i) {
        CustomData data{
            "User" + std::to_string(i),
            "user" + std::to_string(i) + "@example.com",
            i * 123456
        };

        logger->info("Log entry #{}: {{Name: {}, Email: {}, Number: {}}}",
                     i, data.name, data.email, data.number);

        for (size_t j = 0; j < config.debug_amplification; ++j) {
            logger->debug("Debugging log entry # {}/{}: {{Name: {}, Email: {}, Number: {}}}",
                          i, j, data.name, data.email, data.number);
        }

        for (size_t j = 0; j < config.trace_amplification; ++j) {
            logger->trace("Tracing log entry # {}/{}: {{Name: {}, Email: {}, Number: {}}} with additional info",
                          i, j, data.name, data.email, data.number);
        }
    }

    // 5) Flush and clean up
    logger->flush();
    spdlog::drop("perf_logger");
}

int main(int argc, char *argv[])
{
    Config config;

    namespace po = boost::program_options;
    po::options_description desc("Allowed options");
    desc.add_options()
        ("help,h", "produce help message")
        ("logger,l", po::value(&config.logger)->default_value(config.logger),
         "logger name, one of {logfault, boostlog, spdlog}")
        ("console-level,C", po::value(&config.level_console)->default_value(config.level_console),
         "log level (e.g., trace, debug, info, warning, error)")
        ("file-level,F", po::value(&config.level_file)->default_value(config.level_file),
         "log level for file output (e.g., trace, debug, info, warning, error)")
        ("file-name,f", po::value(&config.file_name),
         "name of the log file. If not provided, logging to file is disabled")
        ("json,j", po::bool_switch(&config.as_json)->default_value(config.as_json),
         "output logs in JSON format")
        ("num_log_entries,n", po::value(&config.num_log_entries)->default_value(config.num_log_entries),
          "number of log entries to generate")
        ("debug-aplification,d", po::value(&config.debug_amplification)->default_value(config.debug_amplification),
          "number of debug log entries per main log entry")
        ("trace-amplification,t", po::value(&config.trace_amplification)->default_value(config.trace_amplification),
          "number of trace log entries per main log entry")
        ;
    po::variables_map vm;
    po::store(po::parse_command_line(argc, argv, desc), vm);
    po::notify(vm);
    if (vm.count("help")) {
        cout << desc << "\n";
        return 1;
    }
    cout << "Generating " << config.num_log_entries << " log entries..." << endl;

    try {
        if (config.logger == "logfault") {
            logWithLogfault(config);
        } else if (config.logger == "boostlog") {
            logWithBoostLog(config);
        } else if (config.logger == "spdlog") {
            logWithSpdlog(config);
        } else {
            throw std::invalid_argument("Unknown logger: " + config.logger);
        }
    } catch (const std::exception &e) {
        cerr << "Error: " << e.what() << endl;
        return 1;
    }

    return 0;
}

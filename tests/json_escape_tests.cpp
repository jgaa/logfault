#include <gtest/gtest.h>
#include <sstream>
#include <string>
#if __cplusplus >= 201703L
#   include <string_view>
#endif

// pull in the JsonEscape template from your library
#include "logfault/logfault.h"

using namespace logfault;
using namespace std::string_literals;


namespace {
// Helper to run the escape and return the result
std::string escape_string(const std::string& in) {
    std::ostringstream out;
    JsonEscape(in, out);
    return out.str();
}


#if __cplusplus >= 201703L
std::string escape_string(std::string_view in) {
    std::ostringstream out;
    JsonEscape(in, out);
    return out.str();
}
#endif

} // anon ns

TEST(JsonEscapeTest, EmptyString) {
    EXPECT_EQ(escape_string(std::string_view{""}), "");
}

TEST(JsonEscapeTest, NoEscapeNeeded) {
    const std::string msg = "Hello, World! 123 ABC xyz";
    EXPECT_EQ(escape_string(msg), msg);
}

TEST(JsonEscapeTest, QuoteEscape) {
    const std::string msg = R"(She said "Hi!")";
    EXPECT_EQ(escape_string(msg), R"(She said \"Hi!\")");
}

TEST(JsonEscapeTest, BackslashEscape) {
    const std::string msg = R"(C:\Program Files\)";
    // each '\' should become "\\"
    EXPECT_EQ(escape_string(msg), R"(C:\\Program Files\\)");
}

TEST(JsonEscapeTest, SpecialCharacterEscapes) {
    struct { char c; const char* expect; } cases[] = {
        { '\b', R"(\b)" },  // backspace
        { '\t', R"(\t)" },  // tab
        { '\n', R"(\n)" },  // newline
        { '\f', R"(\f)" },  // formfeed
        { '\r', R"(\r)" }   // carriage return
    };
    for (auto &tc : cases) {
        std::string s(1, tc.c);
        EXPECT_EQ(escape_string(s), tc.expect)
            << "Control char code = " << int(static_cast<unsigned char>(tc.c));
    }
}

TEST(JsonEscapeTest, OtherControlCharacterUnicodeEscape) {
    // pick a control code not one of the 5: e.g. 0x01
    unsigned char code = 0x01;
    std::string s(1, static_cast<char>(code));
    // should become "\u0001"
    EXPECT_EQ(escape_string(s), R"(\u0001)");
}

TEST(JsonEscapeTest, MultipleEscapesInOneString) {
    // mix of printable, quote, backslash, newline, and control code 0x02
    std::string s = R"(Line1")";
    s += '\n';
    s += '\x02';
    s += R"(End\)";
    // expected:
    // Line1\" -> Line1\\"
    // \n       -> \n
    // \u0002   -> \u0002
    // End\\    -> End\\\\ ;
    EXPECT_EQ(escape_string(s), "Line1\\\"\\n\\u0002End\\\\"s);
}

#if __cplusplus >= 201703L
TEST(JsonEscapeTest, TemplateWithStringView) {
    std::string_view sv = R"(Tab ->	 End)";
    // note: between "->" and "End" is a literal tab
    EXPECT_EQ(escape_string(sv), R"(Tab ->\t End)");
}
#endif

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}

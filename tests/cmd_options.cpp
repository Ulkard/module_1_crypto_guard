#include "cmd_options.h"
#include <gtest/gtest.h>
#include <print>

namespace {
    enum { APP=0, COMMAND, INPUT, OUTPUT, PASSWORD };
}

std::vector<char*> makeValidArgs() {
    return std::vector<char*> {"app_name", 
        "--command=encrypt", 
        "--input=test_input.txt",
        "--output=test_output.raw",
        "--password=strong_password"};
}

TEST(ProgramOptions, ValidInput) { 
    CryptoGuard::ProgramOptions options;
    auto args = makeValidArgs();
    options.Parse(args.size(), args.data());

    EXPECT_EQ(options.GetCommand(), CryptoGuard::ProgramOptions::COMMAND_TYPE::ENCRYPT);
    EXPECT_EQ(options.GetInputFile(), "test_input.txt");
    EXPECT_EQ(options.GetOutputFile(), "test_output.raw");
    EXPECT_EQ(options.GetPassword(), "strong_password");
}
TEST(ProgramOptions, InvalidCommand) { 
    CryptoGuard::ProgramOptions options;
    auto args = makeValidArgs();
    args[COMMAND] = "--command=bad_cmd";

    EXPECT_EQ(options.Parse(args.size(), args.data()), false);
    args[COMMAND] = "--command=";
    EXPECT_ANY_THROW(options.Parse(args.size(), args.data()));
}
TEST(ProgramOptions, EmptyInput) { 
    CryptoGuard::ProgramOptions options;
    auto args = makeValidArgs();
    args[INPUT] = "";

    EXPECT_EQ(options.Parse(args.size(), args.data()), false);
    EXPECT_EQ(options.GetInputFile(), "");
    args[INPUT] = "--input=";
    EXPECT_ANY_THROW(options.Parse(args.size(), args.data()));
}
TEST(ProgramOptions, EmptyOutput) { 
    CryptoGuard::ProgramOptions options;
    auto args = makeValidArgs();
    args[OUTPUT] = "";

    EXPECT_EQ(options.Parse(args.size(), args.data()), false);
    EXPECT_EQ(options.GetOutputFile(), "");
    args[OUTPUT] = "--output=";
    EXPECT_ANY_THROW(options.Parse(args.size(), args.data()));
}
TEST(ProgramOptions, EmptyPassword) { 
    CryptoGuard::ProgramOptions options;
    auto args = makeValidArgs();
    args[PASSWORD] = "";

    EXPECT_EQ(options.Parse(args.size(), args.data()), false);
    EXPECT_EQ(options.GetPassword(), "");
    args[PASSWORD] = "--password=";
    EXPECT_ANY_THROW(options.Parse(args.size(), args.data()));
}
#include <gtest/gtest.h>
#include <sstream>
#include <stdexcept>

#include "crypto_guard_ctx.h"


TEST(CryptoGuardCtx, ValidInputShort) { 
    std::stringstream in {"short msg"}, out, new_out;
    CryptoGuard::CryptoGuardCtx ctx;

    ctx.EncryptFile(in, out, "strong_password");
    ctx.DecryptFile(out, new_out, "strong_password");
    EXPECT_EQ(in.str(), new_out.str()); 
}

TEST(CryptoGuardCtx, ValidInputLong) {
    std::stringstream in {"0123456789 12 15 18 21 24 27 30 33 36 39 42"}, out, new_out;
    CryptoGuard::CryptoGuardCtx ctx;

    ctx.EncryptFile(in, out, "strong_password");
    ctx.DecryptFile(out, new_out, "strong_password");
    EXPECT_EQ(in.str(), new_out.str());
} 

TEST(CryptoGuardCtx, BrokenInput) {
    std::stringstream in {"short msg"}, out;
    CryptoGuard::CryptoGuardCtx ctx;

    in.setstate(std::_S_failbit);
    EXPECT_THROW(ctx.EncryptFile(in, out, "strong_password"), std::runtime_error);
    in.clear();
    EXPECT_NO_THROW(ctx.EncryptFile(in, out, "strong_password"));
}

TEST(CryptoGuardCtx, BrokenOutput) {
    std::stringstream in {"short msg"}, out;
    CryptoGuard::CryptoGuardCtx ctx;

    out.setstate(std::_S_failbit);
    EXPECT_THROW(ctx.EncryptFile(in, out, "another_password"), std::runtime_error);
    out.clear();
    EXPECT_NO_THROW(ctx.EncryptFile(in, out, "another_password"));
}

TEST(CryptoGuardCtx, ValidInputHashShort) {
    std::stringstream in {"short msg"};
    std::string expected_hash = "0b6a1bcba0cd4fa7f5fcd7c40d4ac321565ca7bc69d8cf92ccc73440445cfb4a";
    
    CryptoGuard::CryptoGuardCtx ctx;
    EXPECT_EQ(ctx.CalculateChecksum(in), expected_hash);
}

TEST(CryptoGuardCtx, ValidInputHashLong) {
    std::stringstream in {"0123456789 12 15 18 21 24 27 30 33 36 39 42"};
    std::string expected_hash = "76e5df5ada3b149c2b342814720b4d1b7fa867295417ab7cf1ab764bae8ab6c3";
    
    CryptoGuard::CryptoGuardCtx ctx;
    EXPECT_EQ(ctx.CalculateChecksum(in), expected_hash);
}

TEST(CryptoGuardCtx, HashNothing) {
    std::stringstream in {""};
    std::string expected_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
   
    CryptoGuard::CryptoGuardCtx ctx;
    EXPECT_EQ(ctx.CalculateChecksum(in), expected_hash);
    in.setstate(std::_S_failbit | std::_S_eofbit);
    EXPECT_NO_THROW(ctx.CalculateChecksum(in));
    EXPECT_EQ(ctx.CalculateChecksum(in), expected_hash);
}
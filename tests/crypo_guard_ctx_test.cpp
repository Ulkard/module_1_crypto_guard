#include <gtest/gtest.h>
#include <ios>
#include <sstream>
#include <stdexcept>

#include "crypto_guard_ctx.h"
#include "openssl/evp.h"


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
    EXPECT_THROW(ctx.EncryptFile(in, out, "strong_password"), std::runtime_error);
    out.clear();
    EXPECT_NO_THROW(ctx.EncryptFile(in, out, "strong_password"));
}
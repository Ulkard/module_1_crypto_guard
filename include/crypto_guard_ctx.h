#pragma once

#include <memory>
#include <string>

namespace CryptoGuard {

class CryptoGuardCtx {
public:
    CryptoGuardCtx();
    ~CryptoGuardCtx() = default;

    CryptoGuardCtx(const CryptoGuardCtx &) = delete;
    CryptoGuardCtx &operator=(const CryptoGuardCtx &) = delete;

    CryptoGuardCtx(CryptoGuardCtx &&) noexcept = default;
    CryptoGuardCtx &operator=(CryptoGuardCtx &&) noexcept = default;

    // API
    void EncryptFile(std::iostream &in, std::iostream &out, std::string_view password);
    void DecryptFile(std::iostream &in, std::iostream &out, std::string_view password);
    std::string CalculateChecksum(std::iostream &in);

private:
    class Impl;
    std::unique_ptr<Impl> pImpl_;
};

}  // namespace CryptoGuard

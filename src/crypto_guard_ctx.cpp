#include "crypto_guard_ctx.h"

#include <openssl/evp.h>

namespace CryptoGuard {

struct AesCipherParams {
    static const size_t KEY_SIZE = 32;             // AES-256 key size
    static const size_t IV_SIZE = 16;              // AES block size (IV length)
    const EVP_CIPHER *cipher = EVP_aes_256_cbc();  // Cipher algorithm

    int encrypt;                              // 1 for encryption, 0 for decryption
    std::array<unsigned char, KEY_SIZE> key;  // Encryption key
    std::array<unsigned char, IV_SIZE> iv;    // Initialization vector
};

class CryptoGuardCtx::Impl {
public:
    void EncryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) {}
    void DecryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) {}
    std::string CalculateChecksum(std::iostream &inStream) { return "NOT_IMPLEMENTED"; }

private:
    using UniquePtrEvp = std::unique_ptr<EVP_CIPHER_CTX, decltype(
        [](EVP_CIPHER_CTX* ptr){ EVP_CIPHER_CTX_free(ptr); })>;
    UniquePtrEvp ctx_{ EVP_CIPHER_CTX_new() };

    AesCipherParams CreateChiperParamsFromPassword(std::string_view password) {
        AesCipherParams params;
        constexpr std::array<unsigned char, 8> salt = {'1', '2', '3', '4',
                                                       '5', '6', '7', '8'};
        int result = EVP_BytesToKey(
            params.cipher, EVP_sha256(), salt.data(),
            reinterpret_cast<const unsigned char *>(password.data()),
            password.size(), 1, params.key.data(), params.iv.data());

        if (result == 0) {
            throw std::runtime_error{"Failed to create a key from password"};
        }

        return params;
    }
};



CryptoGuardCtx::CryptoGuardCtx() 
    : pImpl_(std::make_unique<Impl>()) {
}

void CryptoGuardCtx::EncryptFile(std::iostream &in, std::iostream &out, std::string_view password) {
    pImpl_->EncryptFile(in, out, password);
}
void CryptoGuardCtx::DecryptFile(std::iostream &in, std::iostream &out, std::string_view password) {
    pImpl_->DecryptFile(in, out, password);
}
std::string CryptoGuardCtx::CalculateChecksum(std::iostream &in) { 
    pImpl_->CalculateChecksum(in);
}

}  // namespace CryptoGuard

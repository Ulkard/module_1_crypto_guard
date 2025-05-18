#include "crypto_guard_ctx.h"

#include <cstring>
#include <filesystem>
#include <openssl/evp.h>
#include <stdexcept>
#include <vector>
#include <print>

namespace CryptoGuard {
  
using UniquePtrCypherCtx = std::unique_ptr<EVP_CIPHER_CTX, decltype(
    [](EVP_CIPHER_CTX* ptr){ EVP_CIPHER_CTX_free(ptr); })>;
using UniquePtrMdCtx = std::unique_ptr<EVP_MD_CTX, decltype(
    [](EVP_MD_CTX* ptr){ EVP_MD_CTX_free(ptr); })>;

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
    void EncryptFile(std::iostream &in, std::iostream &out, std::string_view password) {
        runAes(in, out, password, true);
    }
    void DecryptFile(std::iostream &in, std::iostream &out, std::string_view password) {
        runAes(in, out, password, false);
    }
    std::string CalculateChecksum(std::iostream &inStream) { 
        UniquePtrMdCtx ctx;
        return "NOT_IMPLEMENTED"; 
    }

private:
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

    void runAes(std::iostream &in, std::iostream &out, std::string_view password, bool encrypt) {
        if (!in) {
            throw std::ios_base::failure("can't read from input");
        } else if (!out) {
            throw std::ios_base::failure("can't write to output");
        }
        OpenSSL_add_all_algorithms();

        auto params = CreateChiperParamsFromPassword(password);
        params.encrypt = encrypt;
        UniquePtrCypherCtx ctx{ EVP_CIPHER_CTX_new() };

        // Инициализируем cipher
        if (!EVP_CipherInit_ex(ctx.get(), params.cipher, nullptr, 
            params.key.data(), params.iv.data(), params.encrypt)) {
                throw std::runtime_error(std::string("EVP_CipherUpdate failed: ") + strerror(errno));
        }

        std::vector<unsigned char> outBuf(16 + EVP_MAX_BLOCK_LENGTH);
        std::vector<unsigned char> inBuf(16);
        int outLen;
        
        while (in.readsome(reinterpret_cast<char*>(inBuf.data()), inBuf.size())) {
            // Обрабатываем первые N символов
            if(!EVP_CipherUpdate(ctx.get(), outBuf.data(), &outLen, 
                inBuf.data(), static_cast<int>( in.gcount() ))) {
                throw std::runtime_error(std::string("EVP_CipherUpdate failed: ") + strerror(errno));
            }
            std::cout << "EVP_CipherUpdate.outlen = " << outLen 
                << "  read " << in.gcount() << "\tbytes" << std::endl;
            out.write(reinterpret_cast<char*>(outBuf.data()), outLen);
        }

        // Заканчиваем работу с cipher
        if (!EVP_CipherFinal_ex(ctx.get(), outBuf.data(), &outLen)) {
            throw std::runtime_error(std::string("EVP_CipherUpdate failed: ") + strerror(errno));
        }
        out.write(reinterpret_cast<char*>(outBuf.data()), outLen);

        std::print("runAes() done.\n");
        EVP_cleanup();
    }
};



CryptoGuardCtx::CryptoGuardCtx() 
    : pImpl_(std::make_unique<Impl>()) {
}

CryptoGuardCtx::~CryptoGuardCtx() = default;

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

#include "cmd_options.h"
#include "crypto_guard_ctx.h"

#include <fstream>
#include <ios>
#include <print>
#include <stdexcept>


int main(int argc, char *argv[]) {
    try {
        CryptoGuard::ProgramOptions options;
        if (!options.Parse(argc, argv)) {
            
        };
        std::fstream in(options.GetInputFile(), std::ios_base::in);
        std::fstream out;
        if (!options.GetOutputFile().empty()) {
            out.open(options.GetOutputFile(), std::ios_base::out);
        }
        CryptoGuard::CryptoGuardCtx cryptoCtx;

        using COMMAND_TYPE = CryptoGuard::ProgramOptions::COMMAND_TYPE;
        switch (options.GetCommand()) {
        case COMMAND_TYPE::ENCRYPT:
            cryptoCtx.EncryptFile(in, out, options.GetPassword());
            std::print("File encoded successfully\n");
            break;

        case COMMAND_TYPE::DECRYPT:
            cryptoCtx.DecryptFile(in, out, options.GetPassword());
            std::print("File decoded successfully\n");
            break;

        case COMMAND_TYPE::CHECKSUM:
            std::print("Checksum: {}\n", cryptoCtx.CalculateChecksum(in));
            break;

        default:
            throw std::runtime_error{"Unsupported command"};
        }

    } catch (const std::exception &e) {
        std::print(std::cerr, "Error: {}\n", e.what());
        return 1;
    }

    return 0;
}
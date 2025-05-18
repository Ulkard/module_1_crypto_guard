#include "cmd_options.h"
#include <iostream>
#include <print>

namespace CryptoGuard {
    namespace po = boost::program_options;

ProgramOptions::ProgramOptions() : desc_("Allowed options") {
    desc_.add_options()
        ("help,h", "list options")
        ("command,c", po::value<std::string>(), "possible commands: encrypt, decrypt or checksum")
        ("input,i", po::value<std::string>(), "input file path")
        ("output,o", po::value<std::string>(), "output file path")
        ("password,p", po::value<std::string>(), "encrypt/decrypt password")
        ;
}

ProgramOptions::~ProgramOptions() = default;

bool ProgramOptions::Parse(int argc, char *argv[]) { 
    po::variables_map vm;
    po::store(po::parse_command_line(argc, argv, desc_), vm);
    po::notify(vm);
    if (vm.count("help")) {
      std::cout << desc_ << "\n";
      return true;
    }
    if (vm.count("command") &&
        commandMapping_.contains(vm["command"].as<std::string>())) {
        command_ = commandMapping_.at(vm["command"].as<std::string>());
    } else {
        std::print("Error! command not found\n");
        return false;
    }
    if (vm.count("input")) {
        inputFile_ = vm["input"].as<std::string>();
    } else {
        std::print("Error! input path not set\n");
        return false;
    }
    if (vm.count("output")) {
        outputFile_ = vm["output"].as<std::string>();
    } else if (command_ != COMMAND_TYPE::CHECKSUM) {
        std::print("Error! output path not set\n");
        return false;
    }
    if (vm.count("password")) {
        password_ = vm["password"].as<std::string>();
    } else if (command_ != COMMAND_TYPE::CHECKSUM){
        password_ = "";
        std::print("Warning! empty password\n");
    }
    
    return false; 
}

}  // namespace CryptoGuard

#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include "utils.hpp"
#include "tracee.hpp"
#include <unistd.h>
#include <sys/ptrace.h>


int main(int argc, char *argv[])
{
    std::string path, line;
    std::ifstream script;

    // initialization, will replace stdin if needed
    parse_args(argc, argv, path, script);
    tracee program;
    if (!path.empty()) {
        if (!file_exist(path)) errquit("Program not found");
        if (!program.load(path)) errquit("Failed to load program");
    }

    // // interact with user
    while (std::getline(std::cin, line)) {
        if (program.parse(line)) {
            program.interact();
        }
#if DEBUG == 1
        else {
            std::cout << line << std::endl;
        }
#endif
    }

    

    return 0;
}

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
    pid_t child;

    // initialization, will replace stdin if needed
    parse_args(argc, argv, path, script);
    
    if (!file_exist(path)) errquit("program not found");
    
    if ((child = fork()) < 0) {
        errquit("fork failed");
    } else if (child == 0) {
        // child
        if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) < 0) errquit("traceme");
        execlp(path.c_str(), path.c_str(), NULL);
        errquit("should not reach here");
    } else {
        // parent
        tracee program(child);
        if (!program.trace()) errquit("failed to trace");

        // interactive with user
        while (std::getline(std::cin, line)) {
            if (!program.parse(line)) errquit("command failed");

            program.interact();
        }
    }
    

    return 0;
}

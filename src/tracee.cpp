#include <iostream>
#include <string>
#include <unistd.h>
#include <sstream>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include "tracee.hpp"
#include "utils.hpp"
#include <sys/user.h>

std::map<std::string, enum Command> command_map = {
    {"break", BREAK}, {"cont", CONT}, {"delete", DELETE}, {"disasm", DISASM}, {"dump", DUMP},
    {"exit", EXIT}, {"get", GET}, {"getregs", GETREGS}, {"help", HELP}, {"list", LIST},
    {"load", LOAD}, {"run", RUN}, {"vmmap", VMMAP}, {"set", SET}, {"si", SI}, {"start", START}
};

bool tracee::load(std::string path)
{
    if ((this->child = fork()) < 0) {
        return false;
    } else if (this->child == 0) {
        // child
        if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) < 0) errquit("traceme");
        execlp(path.c_str(), path.c_str(), NULL);
        errquit("execlp");
    }

    if (waitpid(child, &this->wait_status, 0) < 0) return false;
    if (!WIFSTOPPED(this->wait_status)) return false;
    ptrace(PTRACE_SETOPTIONS, this->child, 0, PTRACE_O_EXITKILL);

    struct user_regs_struct regs;
    // get rip
    if (ptrace(PTRACE_GETREGS, this->child, 0, &regs) != 0) return false;

    this->is_loaded = true;

    std::cout << "program '" << path << "' loaded. entry point 0x" << std::hex << regs.rip << std::endl;
    return true;
}

bool tracee::parse(std::string line)
{
    if (!line.empty()) {
        std::istringstream input_stream(line);
        std::string command;
        input_stream >> command;
        std::string arg;
        
        std::map<std::string, enum Command>::iterator iter = command_map.find(command);

        // invalid command
        if (iter == command_map.end()) {
            return false;
        }

        this->command = iter->second;

        // push all arguments
        while (input_stream >> arg) {
            this->args.push_back(arg);
        }
    }

    return true;
}

void tracee::interact()
{
    switch (this->command)
    {
    case BREAK:
        /* code */
        if (this->is_running) {
            // replace instr byte with cc
        }
        break;
    case START:
        if (this->is_loaded) {

            this->is_running = true;
        }
        break;
    
    default:
        break;
    }
}
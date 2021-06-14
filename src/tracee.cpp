#include "tracee.hpp"
#include <iostream>
#include <unistd.h>
#include <sstream>
#include <sys/ptrace.h>
#include <sys/wait.h>

std::map<std::string, enum Command> command_map = {
    {"break", BREAK}, {"cont", CONT}, {"delete", DELETE}, {"disasm", DISASM}, {"dump", DUMP},
    {"exit", EXIT}, {"get", GET}, {"getregs", GETREGS}, {"help", HELP}, {"list", LIST},
    {"load", LOAD}, {"run", RUN}, {"vmmap", VMMAP}, {"set", SET}, {"si", SI}, {"start", START}
};

tracee::tracee(pid_t child)
{
    this->child = child;
}

bool tracee::trace()
{
    ptrace(PTRACE_SETOPTIONS, this->child, 0, PTRACE_O_EXITKILL);
    return (waitpid(child, &this->wait_status, 0) >= 0);
}

bool tracee::parse(std::string line)
{
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

    return true;
}

void tracee::interact()
{
    switch (this->command)
    {
    case BREAK:
        /* code */
        // replace instr byte with cc
        break;
    case START:
        // ptrace()
        
        this->is_running = true;
        break;
    
    default:
        break;
    }
}
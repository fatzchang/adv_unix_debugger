#include <iostream>
#include <string>
#include <unistd.h>
#include <sstream>
#include <sys/ptrace.h>
#include <sys/wait.h>

#include "tracee.hpp"
#include "utils.hpp"
#include <sys/user.h>
#include "breakpoint.hpp"

#define RUN_CHECK \
    if (!this->is_running) { \
        ddebug_msg("need to run first"); \
        return; \
    }

#define LOAD_CHECK \
    if (!this->is_loaded) { \
        ddebug_msg("need to load first"); \
        return; \
    }

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
    // check the status first
    if (this->is_loaded && !WIFSTOPPED(this->wait_status)) {
        return;
    }

    switch (this->command)
    {
        case BREAK:
        {
            std::string addr_str = this->args.at(0);
            unsigned long addr;
            addr = std::stoul(addr_str, NULL, 16);
            this->_break(addr);
            break;
        }
        case CONT:
        {
            this->_cont();
            break;
        }
        case DELETE:
        {
            std::string breakpoint_id_str = this->args.at(0);
            int breakpoint_id = std::stoi(breakpoint_id_str);
            this->_delete(breakpoint_id);
            break;
        }
        case DISASM:
        {
            std::string addr_str = this->args.at(0);
            unsigned long addr = std::stoul(addr_str, NULL, 16);
            this->_disasm(addr);
            break;
        }
        case DUMP:
        {
            std::string addr_str = this->args.at(0);
            unsigned long addr = std::stoul(addr_str, NULL, 16);
            int len = 0;
            if (this->args.size() >= 2) {
                std::string len_str = this->args.at(1);
                std::stoi(len_str);
            }

            this->_dump(addr, len);
            break;
        } 
        case EXIT:
        {
            exit(0);
            break;
        }
        case GET:
        {
            std::string reg_name = this->args.at(0);
            this->_get(reg_name);
            break;
        }
        case GETREGS:
        {
            this->_getregs();
            break;
        }
        case HELP:
        {
            this->_help();
            break;
        }
        case LIST:
        {
            this->_list();
            break;
        }
        case LOAD:
        {
            std::string path = this->args.at(0);
            this->_load(path);
            break;
        }
        case RUN:
        {
            this->_run();
            break;
        }
        case VMMAP:
        {
            this->_vmmap();
            break;
        }
        case SET:
        {
            std::string reg_name = this->args.at(0);
            std::string val_str = this->args.at(1);
            long value = std::stol(val_str);
            this->_set(reg_name, value);
            break;
        }
        case SI:
        {
            this->_si();
            break;
        }
        case START:
        {
            this->_start();
            break;
        }    
        default:
            break;
    }
    
    this->args.clear();
    return;
}

void tracee::_break(unsigned long addr)
{
    RUN_CHECK
    // get original code
    long code = ptrace(PTRACE_PEEKTEXT, this->child, addr, 0);
    char *pOpcode = ((char *)&code);

    // create a breakpoint instance
    breakpoint *pBp = new breakpoint(addr, *pOpcode);
    int breakpoint_id = pBp->get_id();

    // save into breakpoint map
    this->breakpoint_addr_map.insert(std::pair<unsigned long, breakpoint *>(addr, pBp));
    this->breakpoint_index_map.insert(std::pair<int, breakpoint *>(addr, pBp));
    
    // replace with 0xcc
    *pOpcode = 0xcc;

    std::cout << "Breakpoint set: " << "0x" << std::hex << addr << std::endl;
}

void tracee::_cont()
{
    RUN_CHECK
    ptrace(PTRACE_CONT, this->child, 0, 0);
}

void tracee::_delete(int breakpoint_id)
{
    // should free the breakpoint
    RUN_CHECK
}

void tracee::_disasm(unsigned long addr)
{
    RUN_CHECK
}

void tracee::_dump(unsigned long addr, int length)
{
    RUN_CHECK
}

void tracee::_get(std::string reg_name)
{
    RUN_CHECK
}

void tracee::_getregs()
{
    RUN_CHECK
}

void tracee::_help()
{

}

void tracee::_list()
{

}

void tracee::_load(std::string path)
{
    LOAD_CHECK
    this->load(path);
}

void tracee::_run()
{
    LOAD_CHECK
    if (this->is_running) {
        ddebug_msg("program is already running");
    }
    
    this->is_running = true;
    ptrace(PTRACE_CONT, this->child, 0, 0);
}

void tracee::_vmmap()
{
    RUN_CHECK
}

void tracee::_set(std::string reg_name, long value)
{
    RUN_CHECK
}

void tracee::_si()
{
    RUN_CHECK
    ptrace(PTRACE_SINGLESTEP, this->child, 0, 0);
}

void tracee::_start()
{
    LOAD_CHECK
    this->is_running = true;
}
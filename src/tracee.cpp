#include <iostream>
#include <string>
#include <sstream>
#include <iomanip>
#include <unistd.h>
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


std::map<std::string, int> register_map = {
    {"r15", 0}, {"r14", 1}, {"r13", 2}, {"r12", 3}, {"rbp", 4}, {"rbx", 5}, {"r11", 6},
    {"r10", 7}, {"r9", 8}, {"r8", 9}, {"rax", 10}, {"rcx", 11}, {"rdx", 12}, {"rsi", 13},
    {"rdi", 14}, {"orig_rax", 15}, {"rip", 16}, {"cs", 17}, {"eflags", 18}, {"rsp", 19}, 
    {"ss", 20}, {"fs_base", 21}, {"gs_base", 22}, {"ds", 23}, {"es", 24}, {"fs", 25}, {"gs", 26}
};

bool tracee::load(std::string path)
{
    if ((this->pid = fork()) < 0) {
        return false;
    } else if (this->pid == 0) {
        // child
        if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) < 0) errquit("traceme");
        execlp(path.c_str(), path.c_str(), NULL);
        errquit("execlp");
    }

    if (waitpid(pid, &this->wait_status, 0) < 0) return false;
    if (!WIFSTOPPED(this->wait_status)) return false;
    ptrace(PTRACE_SETOPTIONS, this->pid, 0, PTRACE_O_EXITKILL);

    struct user_regs_struct regs;
    // get rip
    if (ptrace(PTRACE_GETREGS, this->pid, 0, &regs) != 0) return false;

    this->is_loaded = true;

    std::stringstream msg;
    msg << "program '" << path << "' loaded. entry point 0x" << std::hex << regs.rip;
    ddebug_msg(msg.str());
    return true;
}

bool tracee::parse(std::string line)
{
    if (line.empty()) {
        return false;
    }

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
    long code = ptrace(PTRACE_PEEKTEXT, this->pid, addr, 0);
    char *pOpcode = ((char *)&code);

    // create a breakpoint instance
    breakpoint *pBp = new breakpoint(addr, *pOpcode);
    int breakpoint_id = pBp->get_id();

    // save into breakpoint maps for further searching
    this->breakpoint_addr_map.insert(std::pair<unsigned long, breakpoint *>(addr, pBp));
    this->breakpoint_index_map.insert(std::pair<int, breakpoint *>(breakpoint_id, pBp));
    
    // replace with 0xcc
    *pOpcode = 0xcc;
    if (ptrace(PTRACE_POKETEXT, pid, addr, code) != 0) ddebug_msg("failed to poke text");

    std::stringstream msg;
    msg << "Breakpoint " << breakpoint_id << " at ";
    msg << "0x" << std::hex << addr;
    ddebug_msg(msg.str());
}

void tracee::_cont()
{
    RUN_CHECK
    ptrace(PTRACE_CONT, this->pid, 0, 0);
    waitpid(this->pid, &this->wait_status, 0);
}

void tracee::_delete(int breakpoint_id)
{
    RUN_CHECK
    std::stringstream msg;

    // get breakpoint instance
    std::map<int, breakpoint *>::iterator iter;
    iter = this->breakpoint_index_map.find(breakpoint_id);
    if (iter == this->breakpoint_index_map.end()){
        msg << "No breakpoint number " << breakpoint_id << ".";
        ddebug_msg(msg.str());
        return;
    }

    breakpoint *pBp = iter->second;
    unsigned long addr = pBp->get_addr();
    // restore original code
    long code = ptrace(PTRACE_PEEKTEXT, this->pid, addr, 0);
    ((char *)&code)[0] = pBp->get_opcode();

    // delete  and free breakpoint
    this->breakpoint_addr_map.erase(addr);
    this->breakpoint_index_map.erase(breakpoint_id);
    delete pBp;
    

    msg << "Breakpoint " << breakpoint_id << " deleted.";
    ddebug_msg(msg.str());
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
    struct user_regs_struct regs;
    if (ptrace(PTRACE_GETREGS, this->pid, 0, &regs) != 0) {
        ddebug_msg("failed to get registers");
    }

    std::cout << std::left;
    std::cout << std::setw(6) << "RAX" << std::setw(15) << std::hex << regs.rax;
    std::cout << std::setw(6) << "RBX" << std::setw(15) << std::hex << regs.rbx;
    std::cout << std::setw(6) << "RCX" << std::setw(15) << std::hex << regs.rcx;
    std::cout << std::setw(6) << "RDX" << std::setw(15) << std::hex << regs.rdx << std::endl;

    std::cout << std::setw(6) << "R8" << std::setw(15) << std::hex << regs.r8;
    std::cout << std::setw(6) << "R9" << std::setw(15) << std::hex << regs.r9;
    std::cout << std::setw(6) << "R10" << std::setw(15) << std::hex << regs.r10;
    std::cout << std::setw(6) << "R11" << std::setw(15) << std::hex << regs.r11 << std::endl;

    std::cout << std::setw(6) << "R12" << std::setw(15) << std::hex << regs.r12;
    std::cout << std::setw(6) << "R13" << std::setw(15) << std::hex << regs.r13;
    std::cout << std::setw(6) << "R14" << std::setw(15) << std::hex << regs.r14;
    std::cout << std::setw(6) << "R15" << std::setw(15) << std::hex << regs.r15 << std::endl;

    std::cout << std::setw(6) << "RDI" << std::setw(15) << std::hex << regs.rdi;
    std::cout << std::setw(6) << "RSI" << std::setw(15) << std::hex << regs.rsi;
    std::cout << std::setw(6) << "RBP" << std::setw(15) << std::hex << regs.rbp;
    std::cout << std::setw(6) << "RSP" << std::setw(15) << std::hex << regs.rsp << std::endl;

    std::cout << std::setw(6) << "RIP" << std::setw(15) << std::hex << regs.rip;
    std::cout << std::setw(6) << "FLAGS" << std::setw(15) << std::hex << regs.eflags << std::endl;
}

void tracee::_help()
{
    std::cout << "- break {instruction-address}: add a break point" << std::endl;
    std::cout << "- cont: continue execution" << std::endl;
    std::cout << "- delete {break-point-id}: remove a break point" << std::endl;
    std::cout << "- disasm addr: disassemble instructions in a file or a memory region" << std::endl;
    std::cout << "- dump addr [length]: dump memory content" << std::endl;
    std::cout << "- exit: terminate the debugger" << std::endl;
    std::cout << "- get reg: get a single value from a register" << std::endl;
    std::cout << "- getregs: show registers" << std::endl;
    std::cout << "- help: show this message" << std::endl;
    std::cout << "- list: list break points" << std::endl;
    std::cout << "- load {path/to/a/program}: load a program" << std::endl;
    std::cout << "- run: run the program" << std::endl;
    std::cout << "- vmmap: show memory layout" << std::endl;
    std::cout << "- set reg val: get a single value to a register" << std::endl;
    std::cout << "- si: step into instruction" << std::endl;
    std::cout << "- start: start the program and stop at the first instruction" << std::endl;
}

void tracee::_list()
{
    int i;
    for (i = 0; i < breakpoint::id_count; i++) {
        std::map<int, breakpoint *>::iterator iter;
        iter = this->breakpoint_index_map.find(i);
        if (iter == this->breakpoint_index_map.end()){
            continue;
        }

        breakpoint *pBp = iter->second;
        std::cout << "Breakpoint " << pBp->get_id() << " at ";
        std::cout << "0x" << std::hex << pBp->get_addr() << std::endl;
    }
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
    this->_cont();
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
    ptrace(PTRACE_SINGLESTEP, this->pid, 0, 0);
    waitpid(this->pid, &this->wait_status, 0);
}

void tracee::_start()
{
    LOAD_CHECK
    this->is_running = true;
}
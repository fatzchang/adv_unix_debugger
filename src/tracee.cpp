#include <iostream>
#include <string>
#include <sstream>
#include <iomanip>
#include <fstream>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <capstone/capstone.h>
#include <elf.h>
#include <string.h>




#include "tracee.hpp"
#include "utils.hpp"
#include "breakpoint.hpp"

#define RUN_CHECK \
    if (!this->is_running) { \
        ddebug_msg("Need to run first"); \
        return; \
    }

#define LOAD_CHECK \
    if (!this->is_loaded) { \
        ddebug_msg("Need to load first"); \
        return; \
    }

std::map<std::string, enum Command> command_map = {
    {"break", BREAK}, {"cont", CONT}, {"delete", DELETE}, {"disasm", DISASM}, {"dump", DUMP},
    {"exit", EXIT}, {"get", GET}, {"getregs", GETREGS}, {"help", HELP}, {"list", LIST},
    {"load", LOAD}, {"run", RUN}, {"vmmap", VMMAP}, {"set", SET}, {"si", SI}, {"start", START},
    // short alias
    {"b", BREAK}, {"c", CONT}, {"d", DISASM}, {"x", DUMP}, {"q", EXIT}, {"g", GET}, {"h", HELP}, 
    {"l", LIST}, {"r", RUN}, {"m", VMMAP}, {"s", SET}
};


std::map<std::string, int> register_map = {
    {"r15", 0}, {"r14", 1}, {"r13", 2}, {"r12", 3}, {"rbp", 4}, {"rbx", 5}, {"r11", 6},
    {"r10", 7}, {"r9", 8}, {"r8", 9}, {"rax", 10}, {"rcx", 11}, {"rdx", 12}, {"rsi", 13},
    {"rdi", 14}, {"orig_rax", 15}, {"rip", 16}, {"cs", 17}, {"eflags", 18}, {"rsp", 19}, 
    {"ss", 20}, {"fs_base", 21}, {"gs_base", 22}, {"ds", 23}, {"es", 24}, {"fs", 25}, {"gs", 26}
};

bool tracee::load(std::string path)
{
    this->path = path;

    std::fstream file;
    char elf_header_buffer[64] = { 0 };

    // read elf header
    file.open(path, std::ios::in);
    file.read(elf_header_buffer, 64);

    Elf64_Ehdr elf_header = *(Elf64_Ehdr *)elf_header_buffer;
    this->entry_point = elf_header.e_entry;
    unsigned long section_table_offset = elf_header.e_shoff;
    unsigned int section_header_table_size = elf_header.e_shentsize * elf_header.e_shnum;

    // read section header
    char *section_header_buffer = (char *)malloc(section_header_table_size);
    file.seekg(section_table_offset, std::ios_base::beg);
    file.read(section_header_buffer, section_header_table_size);
    
    Elf64_Shdr *section_header = (Elf64_Shdr *)section_header_buffer;

    // load strtable
    Elf64_Shdr *strtable_entry = section_header + elf_header.e_shstrndx;
    unsigned long strtable_offset = strtable_entry->sh_offset;
    unsigned long strtable_size = strtable_entry->sh_size;
    char *strtable = (char *)malloc(strtable_size);
    file.seekg(strtable_offset, std::ios_base::beg);
    file.read(strtable, strtable_size);
    strtable += 1; // first byte is null

    int text_section_index = 0;    
    for (int i = 0; i < elf_header.e_shnum; i++) {
        std::string section_name = (strtable + (section_header + i)->sh_name);
        if (section_name == "text") {
            text_section_index = i;
        }
    }

    this->text_section_size = (section_header + text_section_index)->sh_size;

    free(section_header_buffer);
    free(strtable - 1);
    file.close();

    // // set loaded
    this->is_loaded = true;

    std::stringstream msg;
    msg << "Program '" << path << "' loaded. entry point 0x" << std::hex << this->entry_point;
    // std::cout << std::hex << (this->entry_point + this->text_section_size) << std::endl;
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
    switch (this->command)
    {
        case BREAK:
        {
            std::string addr_str = this->args.at(0);
            unsigned long addr = str_to_ul(addr_str);
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
            if (this->args.size() > 0) {
                std::string addr_str = this->args.at(0);
                unsigned long addr = str_to_ul(addr_str);
                this->_disasm(addr);
            } else {
                ddebug_msg("no addr is given.");
            }

            break;
        }
        case DUMP:
        {
            if (this->args.size() > 0) {
                std::string addr_str = this->args.at(0);
                unsigned long addr = str_to_ul(addr_str);
                this->_dump(addr);
            } else {
                ddebug_msg("no addr is given.");
            }

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
            unsigned long value = str_to_ul(val_str);
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
    unsigned char *pOpcode = ((unsigned char *)&code);

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
    
    this->switch_n_step();

    ptrace(PTRACE_CONT, this->pid, 0, 0);
    if (this->wait_n_check()) {
        this->backward();
        std::string msg = this->breakpoint_msg();
        std::cout << msg << std::endl;
    }
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
    ((unsigned char *)&code)[0] = pBp->get_opcode();
    ptrace(PTRACE_POKETEXT, this->pid, addr, code);

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
    // x86_64 max instruction length is 64 bits, use long type is sufficient 
    long code_segment[10];
    for (int i = 0; i < 10; i++) {
        unsigned long target_addr = (addr + i * 8);
        code_segment[i] = this->get_code(target_addr);

        // disasm should show the original instruction, thus replace all 0xcc with original opcode
        for (int j = 0; j < sizeof(long); j++) {
            unsigned char *code_byte = &((unsigned char *)&code_segment[i])[j];
            if (*code_byte == 0xcc) {
                std::map<unsigned long, breakpoint *>::iterator iter;
                iter = this->breakpoint_addr_map.find(addr + i * 8 + j);
                if (iter == breakpoint_addr_map.end()) {
                    ddebug_msg("Breakpoint not found");
                    continue;
                }

                breakpoint *pBp = iter->second;
                *code_byte = pBp->get_opcode();
            }
        }
    }

    csh handle;
	cs_insn *insn;
	size_t count;

	if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) {
		return;
    }

	count = cs_disasm(handle, (uint8_t *)code_segment, sizeof(code_segment)-1, addr, 10, &insn);
	if (count > 0) {
		size_t j;
        std::cout << std::hex;
		for (j = 0; j < count; j++) {
            if (insn[j].address >= (this->entry_point + this->text_section_size)) {
                break;
            }

            std::cout << std::setw(6) << std::right << std::setfill('0') << insn[j].address << ": " << std::setfill(' ');
            std::stringstream bytes_str;
            for (int k = 0; k < insn[j].size; k++) {
                bytes_str << std::setw(2) << std::right << std::setfill('0') << std::hex;
                bytes_str << (unsigned int)insn[j].bytes[k] << " ";
            }

            std::cout << std::setw(23) << std::left << bytes_str.str();
            std::cout << std::setw(6) << std::left << insn[j].mnemonic << " " << insn[j].op_str << std::endl;
		}
        std::cout << std::dec;

		cs_free(insn, count);
	} else
		printf("ERROR: Failed to disassemble given code!\n");

	cs_close(&handle);
}

void tracee::_dump(unsigned long addr)
{
    RUN_CHECK
    int long_size = sizeof(long);
    std::cout << std::right << std::hex << std::setfill('0');
    for (int i = 0; i < 5; i++) {
        std::cout << std::setw(6) << (addr + i * 16) << ": ";
        // display two words a line
        for (int j = 0; j < 2; j++) {
            long code = this->get_code(addr + i * 16 + j * 8);
            // down to character level
            for (int k = 0; k < long_size; k++) {
                std::cout << std::hex << std::setw(2) << (int)(((unsigned char *)&code)[k]) << " ";
            }
        }

        // // display character if printable
        std::cout << "  | ";

        for (int j = 0; j < 2; j++) {
            long code = get_code(addr + i * 16 + j * 8);
            // down to character level
            for (int k = 0; k < long_size; k++) {
                if (isprint(((char *)&code)[k])) {
                    std::cout << ((char *)&code)[k];
                } else {
                    std::cout << ".";
                }
            }
        }

        std::cout << " |";
        std::cout << std::endl;
    }
    
    std::cout << std::dec;
}

void tracee::_get(std::string reg_name)
{
    RUN_CHECK
    std::map<std::string, int>::iterator iter = register_map.find(reg_name);
    if (iter == register_map.end()) {
        ddebug_msg("Invalid register name");
        return;
    }

    int byte_offset = iter->second * sizeof(unsigned long long int);
    long value = ptrace(PTRACE_PEEKUSER, this->pid, byte_offset, 0);
    std::cout << reg_name << " = " << value << " (0x" << std::hex << value << ")" << std::endl;
    std::cout << std::dec; // restore to decimal
}

void tracee::_getregs()
{
    RUN_CHECK
    struct user_regs_struct regs;
    if (ptrace(PTRACE_GETREGS, this->pid, 0, &regs) != 0) {
        ddebug_msg("Failed to get registers");
    }

    std::cout << std::left << std::hex;
    std::cout << std::setw(6) << "RAX" << std::setw(15) << regs.rax;
    std::cout << std::setw(6) << "RBX" << std::setw(15) << regs.rbx;
    std::cout << std::setw(6) << "RCX" << std::setw(15) << regs.rcx;
    std::cout << std::setw(6) << "RDX" << std::setw(15) << regs.rdx << std::endl;

    std::cout << std::setw(6) << "R8" << std::setw(15) << regs.r8;
    std::cout << std::setw(6) << "R9" << std::setw(15) << regs.r9;
    std::cout << std::setw(6) << "R10" << std::setw(15) << regs.r10;
    std::cout << std::setw(6) << "R11" << std::setw(15) << regs.r11 << std::endl;

    std::cout << std::setw(6) << "R12" << std::setw(15) << regs.r12;
    std::cout << std::setw(6) << "R13" << std::setw(15) << regs.r13;
    std::cout << std::setw(6) << "R14" << std::setw(15) << regs.r14;
    std::cout << std::setw(6) << "R15" << std::setw(15) << regs.r15 << std::endl;

    std::cout << std::setw(6) << "RDI" << std::setw(15) << regs.rdi;
    std::cout << std::setw(6) << "RSI" << std::setw(15) << regs.rsi;
    std::cout << std::setw(6) << "RBP" << std::setw(15) << regs.rbp;
    std::cout << std::setw(6) << "RSP" << std::setw(15) << regs.rsp << std::endl;

    std::cout << std::setw(6) << "RIP" << std::setw(15) << regs.rip;
    std::cout << std::setw(6) << "FLAGS" << std::setw(15) << regs.eflags << std::endl;
    std::cout << std::dec;
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
        std::cout << std::right;
        std::cout << std::setw(3) << pBp->get_id() << ":   ";
        std::cout << std::hex << pBp->get_addr() << std::endl;
        std::cout << std::dec; // restore to decimal
    }
}

void tracee::_load(std::string path)
{
    if (!this->load(path)) ddebug_msg("Failed to load program");
}

void tracee::_run()
{
    LOAD_CHECK
    if (this->is_running) {
        ddebug_msg("Program is already running");
    } else {
        this->_start();
    }
    
    this->_cont();
}

void tracee::_vmmap()
{
    RUN_CHECK
    std::stringstream path;
    path << "/proc/" << this->pid << "/maps";
    std::ifstream maps_stream(path.str(), std::ifstream::in);
    std::string line;
    
    while (std::getline(maps_stream, line)) {
        std::cout << line << std::endl;
    };
    
}

void tracee::_set(std::string reg_name, unsigned long value)
{
    RUN_CHECK

    std::map<std::string, int>::iterator iter = register_map.find(reg_name);
    if (iter == register_map.end()) {
        ddebug_msg("Invalid register name");
        return;
    }

    int byte_offset = iter->second * sizeof(unsigned long long int);
    if (ptrace(PTRACE_POKEUSER, this->pid, byte_offset, value) != 0) {
        ddebug_msg("Failed to set register");
    }
}

// this will move one step further, and restore the previous opcode with 0xcc again for breakpoint reusing
void tracee::_si()
{
    RUN_CHECK
    this->switch_n_step();

    std::string msg = this->breakpoint_msg();
    std::cout << msg << std::endl;
}

void tracee::_start()
{
    LOAD_CHECK
    if (this->is_running) {
        kill(this->pid, SIGKILL);
    }
    
    this->clear_breakpoints();

    if ((this->pid = fork()) < 0) {
        ddebug_msg("Failed to fork tracee");
        return;
    } else if (this->pid == 0) {
        // child
        if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) < 0) errquit("traceme");
        execlp(this->path.c_str(), this->path.c_str(), NULL);
        errquit("execlp");
    }

    if (waitpid(this->pid, &this->wait_status, 0) < 0) return;
    if (!WIFSTOPPED(this->wait_status)) return;
    ptrace(PTRACE_SETOPTIONS, this->pid, 0, PTRACE_O_EXITKILL);

    this->is_running = true;
    std::stringstream msg;
    msg << "pid " << this->pid;
    ddebug_msg(msg.str());
}

bool tracee::wait_n_check()
{
    waitpid(this->pid, &this->wait_status, 0);
    if (WIFEXITED(this->wait_status)) {
        int exit_code = WEXITSTATUS(this->wait_status);
        std::stringstream msg;
        msg << "child process " << this->pid << " terminated normally (code " << exit_code << ")";
        ddebug_msg(msg.str());

        this->is_running = false;
    };

    return !!WIFSTOPPED(this->wait_status);
}

// return: has switched or not
bool tracee::switch_n_step()
{
    // get original code
    long rip;
    int byte_offset = get_rip(rip);
    long code = get_code(rip);

    unsigned char *pOpcode = ((unsigned char *)&code);

    bool is_switched = false;

    //  restore opcode if it's 0xcc
    if (*pOpcode == 0xcc) {
        // get the breakpoint by address
        std::map<unsigned long, breakpoint *>::iterator iter;
        iter = this->breakpoint_addr_map.find(rip);
        if (iter == breakpoint_addr_map.end()) {
            ddebug_msg("Breakpoint not found");
            return is_switched;
        }

        breakpoint *pBp = iter->second;
        *pOpcode = pBp->get_opcode();

        // restore opcode
        if (ptrace(PTRACE_POKETEXT, this->pid, rip, code) != 0) {
            ddebug_msg("Failed to resotre code");
            return is_switched;
        }

        is_switched = true;
    }

    // move one step further
    ptrace(PTRACE_SINGLESTEP, this->pid, 0, 0);
    this->wait_n_check();

    // reuse break: replace previous step's opcode with 0xcc
    if (is_switched) {
        *pOpcode = 0xcc;
        ptrace(PTRACE_POKETEXT, this->pid, rip, code); // rip is the previous rip
    }

    return is_switched;
}

int tracee::get_rip(long &rip)
{
    std::map<std::string, int>::iterator iter = register_map.find("rip");
    int byte_offset = iter->second * sizeof(unsigned long long int);
    rip = ptrace(PTRACE_PEEKUSER, this->pid, byte_offset, 0);

    return byte_offset;
}

long tracee::get_code(long addr)
{
    return ptrace(PTRACE_PEEKTEXT, this->pid, addr, 0);
}

// backword one byte if encountered 0xcc
void tracee::backward()
{
    long rip;
    int byte_offset = get_rip(rip);
    long code = get_code(rip);

    unsigned char *pOpcode = ((unsigned char *)&code);
    if (*pOpcode = 0xcc) {
        if (ptrace(PTRACE_POKEUSER, this->pid, byte_offset, rip - 1) != 0)
            ddebug_msg("Failed to backward");
    }
}

std::string tracee::breakpoint_msg()
{
    long rip;
    this->get_rip(rip);
    long code = get_code(rip);
    std::stringstream msg;

    unsigned char *pOpcode = ((unsigned char *)&code);

    // show breakpoint message
    if (*pOpcode == 0xcc) {
        std::map<unsigned long, breakpoint *>::iterator iter;
        iter = this->breakpoint_addr_map.find(rip);
        if (iter == breakpoint_addr_map.end()) {
            ddebug_msg("Breakpoint not found");
            return msg.str();
        }

        breakpoint *pBp = iter->second;
        *pOpcode = pBp->get_opcode();
        

        csh handle;
        cs_insn *insn;
        size_t count;
        
        if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) {
            return msg.str();
        }
        msg << "breakpoint @ ";

        count = cs_disasm(handle, (uint8_t *)&code, sizeof(code)-1, rip, 1, &insn);
        if (count > 0) {
            size_t j;
            msg << std::hex;
            for (j = 0; j < count; j++) {
                msg << std::setw(12) << std::right << insn[j].address << ": ";
                std::stringstream bytes_str;
                for (int k = 0; k < insn[j].size; k++) {
                    bytes_str << std::setw(2) << std::right << std::setfill('0') << std::hex;
                    bytes_str << (unsigned int)insn[j].bytes[k] << " " << std::setfill(' ');
                }

                msg << std::setw(23) << std::left << bytes_str.str();
                msg << std::setw(6) << std::left << insn[j].mnemonic << " " << insn[j].op_str;
            }

            cs_free(insn, count);
        } else
            printf("ERROR: Failed to disassemble given code!\n");

        cs_close(&handle);
    }

    return msg.str();
}


void tracee::clear_breakpoints()
{
    std::map<unsigned long, breakpoint *>::iterator iter;
    for (iter = this->breakpoint_addr_map.begin(); iter != this->breakpoint_addr_map.end(); iter++)
    {
        breakpoint *pBp = iter->second;
        delete pBp;
    }


    this->breakpoint_addr_map.clear();
    this->breakpoint_index_map.clear();

}
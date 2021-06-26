#ifndef __TRACEE_H
#define __TRACEE_H

#include <iostream>
#include <vector>
#include <sys/types.h>
#include <map>

#include "breakpoint.hpp"

enum Command { 
    BREAK,  CONT, DELETE, DISASM, 
    DUMP, EXIT, GET, GETREGS, HELP, 
    LIST, LOAD, RUN, VMMAP, SET, SI, START
};


class tracee {
    public:
        bool load(std::string path);
        bool parse(std::string line);
        void interact();
    private:
        pid_t pid;
        std::string path;
        int wait_status;
        std::vector<std::string> args;
        unsigned long entry_point;
        unsigned long text_section_size;
        bool is_loaded = false;
        bool is_running = false;
        enum Command command;
        std::map<unsigned long, breakpoint *> breakpoint_addr_map; // (address, original_byte)
        std::map<int, breakpoint *> breakpoint_index_map; // (address, original_byte)

        // command handler
        void _break(unsigned long addr);
        void _cont();
        void _delete(int breakpoint_id);
        void _disasm(unsigned long addr);
        void _dump(unsigned long addr);
        void _exit();
        void _get(std::string reg_name);
        void _getregs();
        void _help();
        void _list();
        void _load(std::string path);
        void _run(); 
        void _vmmap();
        void _set(std::string reg_name, unsigned long value);
        void _si();
        void _start();
        

        bool wait_n_check();
        bool switch_n_step();
        int get_rip(long &rip);
        long get_code(long addr);
        void backward();
        std::string breakpoint_msg();
        void clear_breakpoints();
};


#endif
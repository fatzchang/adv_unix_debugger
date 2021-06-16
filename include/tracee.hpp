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
        pid_t child;
        int wait_status;
        std::vector<std::string> args;
        bool is_loaded = false;
        bool is_running = false;
        enum Command command;
        std::map<unsigned long, breakpoint *> breakpoint_addr_map; // (address, original_byte)
        std::map<int, breakpoint *> breakpoint_index_map; // (address, original_byte)

        // command handler
        void _break(unsigned long addr); //
        void _cont(); //
        void _delete(int breakpoint_id); //
        void _disasm(unsigned long addr); //
        // void _dump(unsigned long addr); 
        void _dump(unsigned long addr, int length); //
        void _exit();
        void _get(std::string reg_name);
        void _getregs();
        void _help();
        void _list();
        void _load(std::string path);
        void _run(); 
        void _vmmap();
        void _set(std::string reg_name, long value);
        void _si();
        void _start();
};


#endif
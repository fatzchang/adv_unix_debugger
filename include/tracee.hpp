#ifndef __TRACEE_H
#define __TRACEE_H

#include <iostream>
#include <vector>
#include <sys/types.h>
#include <map>
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
};


#endif
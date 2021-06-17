#ifndef __BREAKPOINT_H
#define __BREAKPOINT_H

class breakpoint {
    public:
        static int id_count;
        breakpoint(unsigned long addr, unsigned char opcode);
        int get_id();
        unsigned long get_addr();
        unsigned char get_opcode();
    private:
        int id;
        unsigned long addr;
        char opcode;
};

#endif
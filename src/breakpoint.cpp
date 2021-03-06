#include "breakpoint.hpp"

// use to distribute id of each instance
int breakpoint::id_count = 1;

breakpoint::breakpoint(unsigned long addr, unsigned char opcode)
{
    this->id = id_count;
    this->addr = addr;
    this->opcode = opcode;

    id_count++;
}

int breakpoint::get_id()
{
    return this->id;
}


unsigned long breakpoint::get_addr()
{
    return this->addr;
}


unsigned char breakpoint::get_opcode()
{
    return this->opcode;
}


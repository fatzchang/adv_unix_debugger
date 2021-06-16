#include "breakpoint.hpp"

// use to distribute id of each instance
int breakpoint::id_count = 1;

breakpoint::breakpoint(unsigned long addr, char opcode)
{
    this->id = id_count;

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


char breakpoint::get_opcode()
{
    return this->opcode;
}


#include "utils.hpp"
#include <string>
#include <unistd.h>
#include <iostream>
// #include <stdio.h>

extern char *optarg;
extern int optind;

void parse_args(int argc, char *argv[], std::string &path, std::ifstream &script)
{
    int o;
    std::string optstr("s:");

    while ((o = getopt(argc, argv, optstr.c_str())) != -1) {
        if (o == 's') {
            // redirect stdin to script file
            script.open(optarg);
            if (script.is_open()) {
                std::cin.rdbuf(script.rdbuf());
            }
        }
    }

    // retrieve program path
    if (argv[optind]) {
        path = argv[optind];
    }
}

bool file_exist(std::string &path)
{
    std::ifstream file(path);
    return file.good();
}

void errquit(std::string message)
{   
    perror(message.c_str());
    exit(-1);
}

void ddebug_msg(std::string message)
{
    std::cout << "** " << message << std::endl;
}

bool is_hex_string(std::string &str)
{
    return (
        str.compare(0, 2, "0x") == 0
        && str.size() > 2
        && str.find_first_not_of("0123456789abcdefABCDEF", 2) == std::string::npos
    );
}

bool is_bin_string(std::string &str)
{
    return (
        str.compare(0, 2, "0b") == 0
        && str.size() > 2
        && str.find_first_not_of("01", 2) == std::string::npos
    );
}

unsigned long str_to_ul(std::string &str)
{
    int base = 10;

    if (is_hex_string(str)) {
        base = 16;
    } else if (is_bin_string(str)) {
        base = 2;
    }
        
    return std::stoul(str, NULL, base);
}
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
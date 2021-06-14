#include <iostream>
#include <fstream>
#include <string>

#include <unistd.h>

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

int main(int argc, char *argv[])
{
    
    std::string path, line;
    std::ifstream script;

    parse_args(argc, argv, path, script);

    // interactive with user
    while (std::getline(std::cin, line)) {
        std::cout << line << std::endl;
    }
    

    return 0;
}

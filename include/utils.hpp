#ifndef __UTILS_H
#define __UTILS_H

#include <string>
#include <fstream>

void parse_args(int argc, char *argv[], std::string &path, std::ifstream &script);
bool file_exist(std::string &path);
void errquit(std::string message);
void ddebug_msg(std::string message);
bool is_hex_string(std::string &str);
bool is_bin_string(std::string &str);
unsigned long str_to_ul(std::string &str);

#endif
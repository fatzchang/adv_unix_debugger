#ifndef __UTILS_H
#define __UTILS_H

#include <string>
#include <fstream>

void parse_args(int argc, char *argv[], std::string &path, std::ifstream &script);
bool file_exist(std::string &path);
void errquit(std::string message);

#endif
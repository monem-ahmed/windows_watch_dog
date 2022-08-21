#include "WindowsUtility.h"
void return_name(std::string exec_path, char *FileName) // return executable filename from fullPath
{
    char FileExt[5];
    _splitpath_s(exec_path.c_str(), nullptr, 0, nullptr, 0, FileName, 60, FileExt, 5);
    strcat(FileName, FileExt);
}
std::string ExePath()
{ // return name of the executable directory
    CHAR buffer[MAX_PATH] = {0};
    GetModuleFileNameA(NULL, buffer, MAX_PATH);
    std::string::size_type pos = std::string(buffer).find_last_of("\\/");
    return std::string(buffer).substr(0, pos);
}
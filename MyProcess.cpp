#include "MyProcess.h"
MyProcess::MyProcess(std::string exe_path, std::string args)
{
    strcpy(this->executable_path, exe_path.c_str());
    strcpy(this->arguments, exe_path.c_str());
    strcat(this->arguments, " ");
    strcat(this->arguments, args.c_str());
    return_name(this->executable_path, name);
    this->handle_created = FALSE;
}

void MyProcess::set_handle(HANDLE h)
{
    this->handle = h;
}
HANDLE MyProcess::get_handle()
{
    return this->handle;
}
void MyProcess::set_ppid(DWORD pid)
{
    this->ppid = pid;
}
DWORD MyProcess::get_ppid()
{
    return this->ppid;
}
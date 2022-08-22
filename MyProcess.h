#pragma once
#include <Windows.h>
#include <iostream>
#include "WindowsUtility.h"
class MyProcess // Class for handling the process
{
    HANDLE handle; // Store Process Handle
    DWORD ppid;    // store process pid

public:
    CHAR executable_path[500]; // store executable file path
    CHAR name[60];             // Store only executable name
    CHAR arguments[1000];      // Store Full Arguments, including executable path and Startup Parameters
    BOOL handle_created;       // Whether Handle Created or not
    MyProcess(std::string exe_path, std::string args);
    // Setters and Getters for Private Members
    void set_handle(HANDLE h);
    HANDLE get_handle();
    void set_ppid(DWORD pid);
    DWORD get_ppid();
    bool is_running();
};
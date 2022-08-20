#include <iostream>
#include <fstream>
#include <Windows.h>
#include <winternl.h>
#include "get_cmd_line.h"
#include "json.hpp"
#include <vector>
#include <stdio.h>
#include <TlHelp32.h>

int Error(const char *text);
const std::string conf_file = ".\\confs\\config.json";
DWORD WINAPI WatchFile(PVOID);
char FileName[60];
char FileExt[5];

char *return_name(std::string exec_path) // return executable filename from fullPath
{
    _splitpath_s(exec_path.c_str(), nullptr, 0, nullptr, 0, FileName, 60, FileExt, 5);
    strcat(FileName, FileExt);
    return FileName;
}
std::string ExePath()
{ // return name of the executable directory
    CHAR buffer[MAX_PATH] = {0};
    GetModuleFileNameA(NULL, buffer, MAX_PATH);
    std::string::size_type pos = std::string(buffer).find_last_of("\\/");
    return std::string(buffer).substr(0, pos);
}
class MyProcess // Class for handling the process
{
    HANDLE handle;
    DWORD ppid;

public:
    CHAR executable_path[500];
    CHAR name[60];
    CHAR arguments[1000];
    BOOL handle_created;
    MyProcess(std::string exe_path, std::string args)
    {
        strcpy(executable_path, exe_path.c_str());
        strcpy(arguments, exe_path.c_str());
        strcat(arguments, " ");
        strcat(arguments, args.c_str());
        char *FileName = return_name(executable_path);
        strcpy(name, FileName);
        handle_created = FALSE;
    }
    void set_handle(HANDLE h)
    {
        handle = h;
    }
    HANDLE get_handle()
    {
        return handle;
    }
    void set_ppid(DWORD pid)
    {
        ppid = pid;
    }
    DWORD get_ppid()
    {
        return ppid;
    }
};

// Function Prototypes
void create_process();
std::vector<MyProcess> ProcessToBeTracked;
void read_config_file();
int check_existing_process();

int main()
{
    read_config_file(); // read config file first
    int check_status = check_existing_process();
    if (check_status == 1)
        printf("Existing Process Checked");
    else
    {
        printf("Returned with Error: %d", check_status);
    }                 // check which processes are already opened, get handle of them
    create_process(); // create rest of the processes

    for (auto p = 0; p < ProcessToBeTracked.size(); ++p)
    {
        std::cout << "Created Process: " << ProcessToBeTracked[p].name << ProcessToBeTracked[p].get_ppid() << std::endl;
    }

    // Start a thread for Monitoring The File
    HANDLE WatchFileThread = CreateThread(nullptr, 0, WatchFile, nullptr, 0, nullptr);
    if (!WatchFileThread)
    {
        printf("Failed to create thread error= %d\n", GetLastError());
        return 1;
    }

    printf("Main Thread Id: %u\n", GetCurrentThreadId());

    // Periodically Monitor the processes
    while (true)
    {
        for (auto i = ProcessToBeTracked.begin(); i != ProcessToBeTracked.end(); i++)
        {
            DWORD status;
            if (GetExitCodeProcess((*i).get_handle(), &status))
                if (status != STILL_ACTIVE) // Find Out Which Processes are killed
                {
                    (*i).handle_created = false;
                }
        }
        create_process(); // Create processes those are killed
        Sleep(10000);     // Monitor after 10 seconds
    }
    return 0;
}

// Create Process from the global list, If handles are not opened already
void create_process()
{
    for (auto i = ProcessToBeTracked.begin(); i != ProcessToBeTracked.end(); i++)
    {
        if (!(*i).handle_created)
        {
            STARTUPINFOA si;
            PROCESS_INFORMATION pi;
            ZeroMemory(&si, sizeof(si));
            si.cb = sizeof(si);
            ZeroMemory(&pi, sizeof(pi));
            char command[200];
            strcpy(command, (*i).arguments);
            // Start the child process.
            if (!CreateProcessA(NULL,    // No module name (use command line)
                                command, // Command line
                                NULL,    // Process handle not inheritable
                                NULL,    // Thread handle not inheritable
                                FALSE,   // Set handle inheritance to FALSE
                                0,       // No creation flags
                                NULL,    // Use parent's environment block
                                NULL,    // Use parent's starting directory
                                &si,     // Pointer to STARTUPINFO structure
                                &pi)     // Pointer to PROCESS_INFORMATION structure
            )
            {
                printf("CreateProcess failed (%d).\n", GetLastError());
                return;
            }
            else
            {

                // Set Process Parameters
                (*i).set_handle(pi.hProcess);
                (*i).set_ppid(pi.dwProcessId);
                (*i).handle_created = TRUE;
                std::cout << "New Process Created for " << (*i).name << std::endl;
            }
        }
    }
}

// Reading Configuration file from ./confs/config.json
void read_config_file()
{
    printf("reading config file");
    std::ifstream f;
    f.open(conf_file);

    nlohmann::json data = nlohmann::json::parse(f, nullptr, false);
    if (!data.is_discarded()) // Check if json data are valid
    {
        for (auto it = data.at("processes").begin(); it != data.at("processes").end(); ++it)
        {

            std::string executable{it.value().at("exec_path")};
            std::string args{it.value().at("args")};
            MyProcess p(executable, args);
            ProcessToBeTracked.push_back(p);
        }
    }
    else
    {
        printf("Corrupted JSON Data");
    }
}

// Print Error Code from windows API

int Error(const char *text)
{
    printf("%s (%d)\n", text, ::GetLastError());
    return 1;
}

// Check Which Processes are already opened using their name, get handle of them
int check_existing_process()
{
    HANDLE hSnapshot = ::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    printf("Checking for existing processes\n");
    if (hSnapshot == INVALID_HANDLE_VALUE)
        Error("Failed to create snapshot");

    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(pe);

    if (!::Process32First(hSnapshot, &pe))
        Error("Failed in Process32First");

    do
    {
        std::vector<MyProcess>::iterator ite;
        CHAR val[260];
        strcpy(val, pe.szExeFile);
        // compare if the process exists in the config file
        ite = std::find_if_not(ProcessToBeTracked.begin(), ProcessToBeTracked.end(), [val](MyProcess x)
                               { return strcmp(x.name, val); });
        if (ite != ProcessToBeTracked.end() && !(*ite).handle_created)
        {
            printf("Found One Process already existing : %s\n", (*ite).name);

            SYSTEM_INFO si;
            GetNativeSystemInfo(&si);
            BOOL wow;
            IsWow64Process(GetCurrentProcess(), &wow);
            std::cout << "IsWoW: " << wow << std::endl;
            // use WinDbg "dt ntdll!_PEB" command and search for ProcessParameters offset to find the truth out
            DWORD ProcessParametersOffset = si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64 ? 0x20 : 0x10;
            DWORD CommandLineOffset = si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64 ? 0x70 : 0x40;
            DWORD pebSize = ProcessParametersOffset + 8;
            PBYTE peb = (PBYTE)malloc(pebSize);
            ZeroMemory(peb, pebSize);

            // read basic info to get CommandLine address, we only need the beginning of ProcessParameters
            DWORD ppSize = CommandLineOffset + 16;
            PBYTE pp = (PBYTE)malloc(ppSize);
            ZeroMemory(pp, ppSize);

            PWSTR cmdLine;

            HANDLE hProcess = (OpenProcess(SYNCHRONIZE | PROCESS_QUERY_INFORMATION |
                                               PROCESS_VM_READ,
                                           FALSE, pe.th32ProcessID));
            DWORD err;
            if (wow)
            {
                // we're running as a 32-bit process in a 64-bit OS
                PROCESS_BASIC_INFORMATION_WOW64 pbi;
                ZeroMemory(&pbi, sizeof(pbi));

                // get process information from 64-bit world
                _NtQueryInformationProcess query = (_NtQueryInformationProcess)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtWow64QueryInformationProcess64");
                err = query(hProcess, 0, &pbi, sizeof(pbi), NULL);
                if (err != 0)
                {
                    printf("NtWow64QueryInformationProcess64 failed\n");
                    CloseHandle(hProcess);
                    return -1;
                }

                // read PEB from 64-bit address space
                _NtWow64ReadVirtualMemory64 read = (_NtWow64ReadVirtualMemory64)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtWow64ReadVirtualMemory64");
                err = read(hProcess, pbi.PebBaseAddress, peb, pebSize, NULL);
                if (err != 0)
                {
                    printf("NtWow64ReadVirtualMemory64 PEB failed\n");
                    CloseHandle(hProcess);
                    return -1;
                }

                // read ProcessParameters from 64-bit address space
                // PBYTE* parameters = (PBYTE*)*(LPVOID*)(peb + ProcessParametersOffset); // address in remote process address space
                PVOID64 parameters = (PVOID64) * ((PVOID64 *)(peb + ProcessParametersOffset)); // corrected 64-bit address, see comments
                err = read(hProcess, parameters, pp, ppSize, NULL);
                if (err != 0)
                {
                    printf("NtWow64ReadVirtualMemory64 Parameters failed\n");
                    CloseHandle(hProcess);
                    return -1;
                }

                // read CommandLine
                UNICODE_STRING_WOW64 *pCommandLine = (UNICODE_STRING_WOW64 *)(pp + CommandLineOffset);
                cmdLine = (PWSTR)malloc(pCommandLine->MaximumLength);
                err = read(hProcess, pCommandLine->Buffer, cmdLine, pCommandLine->MaximumLength, NULL);
                if (err != 0)
                {
                    printf("NtWow64ReadVirtualMemory64 Parameters failed\n");
                    CloseHandle(hProcess);
                    return -1;
                }
            }
            else
            {
                // we're running as a 32-bit process in a 32-bit OS, or as a 64-bit process in a 64-bit OS
                PROCESS_BASIC_INFORMATION pbi;
                ZeroMemory(&pbi, sizeof(pbi));

                // get process information
                _NtQueryInformationProcess query = (_NtQueryInformationProcess)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryInformationProcess");
                err = query(hProcess, 0, &pbi, sizeof(pbi), NULL);
                if (err != 0)
                {
                    printf("NtQueryInformationProcess failed\n");
                    CloseHandle(hProcess);
                    return -1;
                }

                // read PEB
                if (!ReadProcessMemory(hProcess, pbi.PebBaseAddress, peb, pebSize, NULL))
                {
                    printf("ReadProcessMemory PEB failed\n");
                    CloseHandle(hProcess);
                    return -1;
                }

                // read ProcessParameters
                PBYTE *parameters = (PBYTE *)*(LPVOID *)(peb + ProcessParametersOffset); // address in remote process adress space
                if (!ReadProcessMemory(hProcess, parameters, pp, ppSize, NULL))
                {
                    printf("ReadProcessMemory Parameters failed\n");
                    CloseHandle(hProcess);
                    return -1;
                }

                // read CommandLine
                UNICODE_STRING *pCommandLine = (UNICODE_STRING *)(pp + CommandLineOffset);
                cmdLine = (PWSTR)malloc(pCommandLine->MaximumLength);
                if (!ReadProcessMemory(hProcess, pCommandLine->Buffer, cmdLine, pCommandLine->MaximumLength, NULL))
                {
                    printf("ReadProcessMemory Parameters failed\n");
                    CloseHandle(hProcess);
                    return -1;
                }
            }
            char cmd_buf[1000];
            wcstombs(cmd_buf, cmdLine, 1000);
            char *nEnd = std::remove(std::begin(cmd_buf), std::end(cmd_buf), '"');
            *nEnd = '\0';
            printf("%s\n", cmd_buf);
            printf("%s\n", (*ite).arguments);
            if (!strcmp((*ite).arguments, cmd_buf))
            {
                printf("Both the exe file and args matched");
                    (*ite).set_ppid(pe.th32ProcessID);
                    (*ite).set_handle(hProcess);
                    (*ite).handle_created = TRUE;
                    std::cout << "Opened Handle For an Existing Process"
                              << " " << pe.szExeFile << std::endl;
            }
        }
    } while (::Process32Next(hSnapshot, &pe));

    ::CloseHandle(hSnapshot);
    return 1;
}

// Update the Process Tracking List After The configuration fie is modified
void update_process_list(std::vector<MyProcess> BufVec)
{

    std::cout << "Updating the existing list" << std::endl;
    std::vector<MyProcess> NewProcess;
    std::ifstream f;
    f.open(conf_file);
    nlohmann::json data = nlohmann::json::parse(f, nullptr, false);
    if (!data.is_discarded()) // Check for valid json
    {
        for (auto it = data.at("processes").begin(); it != data.at("processes").end(); ++it)
        {
            std::string executable{it.value().at("exec_path")};
            std::string args{it.value().at("args")};
            char val[60];
            std::vector<MyProcess>::iterator ite;
            char *FileName = return_name(executable);
            strcpy(val, FileName);
            // Check if executable name matches with the config file
            ite = std::find_if_not(BufVec.begin(), BufVec.end(), [val](MyProcess x)
                                   { return strcmp(x.name, val); });
            if (ite != BufVec.end())
            {
                std::cout << "Name Matched"
                          << " " << (*ite).name << std::endl;
                // Check For Argument Matching if the name matches
                if (strcmp(args.c_str(), (*ite).arguments))
                {
                    std::cout << "Arguments Doesn't Match"
                              << std::endl;

                    MyProcess p(executable, args);
                    NewProcess.push_back(p);
                    std::cout << "found old Executable with new arguments to Process"
                              << " " << p.name << p.arguments << std::endl;
                }
                else
                {
                    std::cout << "Arguments Matched"
                              << std::endl;
                    BufVec.erase(ite);
                }
            }
            else
            {
                MyProcess p(executable, args);
                NewProcess.push_back(p);
                std::cout << "found New Executable"
                          << " " << p.name << std::endl;
            }
        }
        // Remove the processes from list according to config file
        for (auto i = BufVec.begin(); i != BufVec.end(); i++)
        {
            DWORD val_ppid = (*i).get_ppid();
            std::cout << val_ppid << " " << std::endl;
            ProcessToBeTracked.erase(
                std::remove_if(ProcessToBeTracked.begin(), ProcessToBeTracked.end(), [val_ppid](MyProcess o)
                               { return o.get_ppid() == val_ppid; }),
                ProcessToBeTracked.end());
        }
        // Add the new files added in the config file

        for (auto i = NewProcess.begin(); i != NewProcess.end(); i++)
        {
            ProcessToBeTracked.push_back(*i);
        }
        create_process();
    }
}

// Watch the Config File Dynamically
DWORD WINAPI WatchFile(PVOID)
{
    printf("WatchFile Thread Id: %u\n", GetCurrentThreadId());
    DWORD dwWaitStatus;
    HANDLE dwChangeHandle;
    std::string path = ExePath() + "\\confs";
    dwChangeHandle = FindFirstChangeNotificationA(
        path.c_str(),                                             // directory to watch
        FALSE,                                                    // do not watch subtree
        FILE_NOTIFY_CHANGE_SIZE | FILE_NOTIFY_CHANGE_LAST_WRITE); // watch file name changes

    if (dwChangeHandle == INVALID_HANDLE_VALUE)
    {
        printf("\n ERROR: FindFirstChangeNotification function failed.\n");
        ExitProcess(GetLastError());
    }

    while (TRUE)
    {
        printf("\nWaiting for notification...\n");
        dwWaitStatus = WaitForSingleObject(dwChangeHandle, INFINITE);

        switch (dwWaitStatus)
        {
        case WAIT_OBJECT_0:

            std::cout << "Triggered" << std::endl;

            update_process_list(ProcessToBeTracked);
            if (FindNextChangeNotification(dwChangeHandle) == FALSE)
            {

                printf("\n ERROR: FindNextChangeNotification function failed.\n");
                ExitProcess(GetLastError());
            }
            break;

        default:
            printf("\n ERROR: Unhandled dwWaitStatus.\n");
            ExitProcess(GetLastError());
            break;
        }
    }
}
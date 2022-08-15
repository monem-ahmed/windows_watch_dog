#include <iostream>
#include <fstream>
#include <Windows.h>
// #include <cstringt.h>
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
    CHAR arguments[500];
    BOOL handle_created;
    MyProcess(std::string exe_path, std::string args)
    {
        strcpy(executable_path, exe_path.c_str());
        strcpy(arguments, args.c_str());
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
void check_existing_process();

int main()
{
    read_config_file();       // read config file first
    check_existing_process(); // check which processes are already opened, get handle of them
    create_process();         // create rest of the processes

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
            strcpy(command, (*i).executable_path);
            strcat(command, " ");
            strcat(command, (*i).arguments);
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
    std::cout << data << std::endl;
    if (!data.is_discarded()) // Check if json data are valid
    {
        printf("JSON Data Read Successful");
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
void check_existing_process()
{
    HANDLE hSnapshot = ::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
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
            (*ite).set_ppid(pe.th32ProcessID);
            (*ite).set_handle(OpenProcess(SYNCHRONIZE, FALSE, pe.th32ProcessID));
            (*ite).handle_created = TRUE;
            std::cout << "Opened Handle For an Existing Process"
                      << " " << pe.szExeFile << std::endl;
        }

    } while (::Process32Next(hSnapshot, &pe));

    ::CloseHandle(hSnapshot);
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

//Watch the Config File Dynamically
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
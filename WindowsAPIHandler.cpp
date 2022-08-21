#include "WindowsAPIHandler.h"


// Create Process from the global list, If handles are not opened already
void create_process(std::vector<MyProcess> *ProcessToBeTracked)
{
    for (auto i = (*ProcessToBeTracked).begin(); i != (*ProcessToBeTracked).end(); i++)
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
                PLOG_ERROR << "CreateProcess failed " << GetLastError();
                return;
            }
            else
            {

                // Set Process Parameters
                (*i).set_handle(pi.hProcess);
                (*i).set_ppid(pi.dwProcessId);
                (*i).handle_created = TRUE;
                PLOG_DEBUG << "New Process Created for " << (*i).name;
            }
        }
    }
}

// Check Which Processes are already opened using their name, get handle of them

bool get_cmd_args(PROCESSENTRY32 pe, char *cmd_buf, HANDLE *hOpenProcess)
{
    SYSTEM_INFO si;
    GetNativeSystemInfo(&si);
    BOOL wow;
    IsWow64Process(GetCurrentProcess(), &wow);
    // search for ProcessParameters offset
    DWORD ProcessParametersOffset = si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64 ? 0x20 : 0x10;
    DWORD CommandLineOffset = si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64 ? 0x70 : 0x40;
    DWORD pebSize = ProcessParametersOffset + 8;
    PBYTE peb = (PBYTE)malloc(pebSize);
    ZeroMemory(peb, pebSize);

    // read basic info to get CommandLine address
    DWORD ppSize = CommandLineOffset + 16;
    PBYTE pp = (PBYTE)malloc(ppSize);
    ZeroMemory(pp, ppSize);

    PWSTR cmdLine;

    HANDLE hProcess = (OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
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
            PLOG_ERROR << "NtWow64QueryInformationProcess64 failed";
            CloseHandle(hProcess);
            return false;
        }

        // read PEB from 64-bit address space
        _NtWow64ReadVirtualMemory64 read = (_NtWow64ReadVirtualMemory64)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtWow64ReadVirtualMemory64");
        err = read(hProcess, pbi.PebBaseAddress, peb, pebSize, NULL);
        if (err != 0)
        {
            PLOG_ERROR << "NtWow64ReadVirtualMemory64 PEB failed\n";
            CloseHandle(hProcess);
            return false;
        }

        // read ProcessParameters from 64-bit address space
        PVOID64 parameters = (PVOID64) * ((PVOID64 *)(peb + ProcessParametersOffset));
        err = read(hProcess, parameters, pp, ppSize, NULL);
        if (err != 0)
        {
            PLOG_ERROR << "NtWow64ReadVirtualMemory64 Parameters failed\n";
            CloseHandle(hProcess);
            return false;
        }

        // read CommandLine
        UNICODE_STRING_WOW64 *pCommandLine = (UNICODE_STRING_WOW64 *)(pp + CommandLineOffset);
        cmdLine = (PWSTR)malloc(pCommandLine->MaximumLength);
        err = read(hProcess, pCommandLine->Buffer, cmdLine, pCommandLine->MaximumLength, NULL);
        if (err != 0)
        {
            PLOG_ERROR << "NtWow64ReadVirtualMemory64 Parameters failed";
            CloseHandle(hProcess);
            return false;
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
            PLOG_ERROR << "NtQueryInformationProcess failed";
            CloseHandle(hProcess);
            return false;
        }

        // read PEB
        if (!ReadProcessMemory(hProcess, pbi.PebBaseAddress, peb, pebSize, NULL))
        {
            PLOG_ERROR << "ReadProcessMemory PEB failed";
            CloseHandle(hProcess);
            return false;
        }

        // read ProcessParameters
        PBYTE *parameters = (PBYTE *)*(LPVOID *)(peb + ProcessParametersOffset); // address in remote process adress space
        if (!ReadProcessMemory(hProcess, parameters, pp, ppSize, NULL))
        {
            PLOG_ERROR << "ReadProcessMemory Parameters failed";
            CloseHandle(hProcess);
            return false;
        }

        // read CommandLine
        UNICODE_STRING *pCommandLine = (UNICODE_STRING *)(pp + CommandLineOffset);
        cmdLine = (PWSTR)malloc(pCommandLine->MaximumLength);
        if (!ReadProcessMemory(hProcess, pCommandLine->Buffer, cmdLine, pCommandLine->MaximumLength, NULL))
        {
            PLOG_ERROR << "ReadProcessMemory CommandLine failed";
            CloseHandle(hProcess);
            return false;
        }
    }
    wcstombs(cmd_buf, cmdLine, 1000);
    *hOpenProcess = hProcess;
    return true;
}
bool check_existing_process(std::vector<MyProcess> *ProcessToBeTracked)
{
    // Read Currently Running Process using ToolHelp Functions
    HANDLE hSnapshot = ::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE)
    {
        PLOG_ERROR << "Failed to create snapshot";
        return false;
    }

    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(pe);

    if (!::Process32First(hSnapshot, &pe))
    {
        PLOG_ERROR << "Failed in Process32First";
        return false;
    }

    do
    {
        std::vector<MyProcess>::iterator ite;
        CHAR val[260];
        char cmd_buf[1000];
        strcpy(val, pe.szExeFile);
        // compare if the process Matches with any executable name of the ProcessToBeTracked List
        ite = std::find_if_not((*ProcessToBeTracked).begin(), (*ProcessToBeTracked).end(), [val](MyProcess x)
                               { return strcmp(x.name, val); });
        if (ite != (*ProcessToBeTracked).end() && !(*ite).handle_created)
        {
            PLOG_DEBUG << "One Executable name process matched : " << (*ite).name;
            HANDLE hOpenProcess;
            // if (hOpenProcess == INVALID_HANDLE_VALUE)
            // {
            //     PLOG_ERROR << "Invalid Handle for Process";
            //     return false;
            // }
            bool cmd_read_status = get_cmd_args(pe, cmd_buf, &hOpenProcess);
            if (!cmd_read_status)
            {
                PLOG_ERROR << "Error Reading command line";
                return false;
            }
            // Remove " character from command line arguments before comparing
            char *nEnd = std::remove(std::begin(cmd_buf), std::end(cmd_buf), '"');
            *nEnd = '\0';
            // Check if Command Line Arguments matches
            if (!strcmp((*ite).arguments, cmd_buf))
            {
                PLOG_DEBUG << "Both the exe file and args matched";
                (*ite).set_ppid(pe.th32ProcessID);

                if (hOpenProcess == INVALID_HANDLE_VALUE)
                {
                    PLOG_ERROR << "Invalid Handle Opened";
                    return false;
                }
                else
                {
                    (*ite).set_handle(hOpenProcess);
                }

                (*ite).handle_created = TRUE;
                PLOG_DEBUG << "Opened Handle For an Existing Process " << pe.szExeFile;
            }
        }
    } while (::Process32Next(hSnapshot, &pe));

    ::CloseHandle(hSnapshot);

    return true;
}
// Watch the Config File Dynamically
DWORD WINAPI WatchFile(PVOID PProcessToBeTracked)
{
    PLOG_DEBUG << "WatchFile Thread Id: ", GetCurrentThreadId();
    DWORD dwWaitStatus;
    HANDLE dwChangeHandle;
    std::string path = ExePath() + "\\confs";
    // Get a Handle for watching Directory, Watch on File Size Change, Last Write
    dwChangeHandle = FindFirstChangeNotificationA(
        path.c_str(),                                             // directory to watch
        FALSE,                                                    // do not watch subtree
        FILE_NOTIFY_CHANGE_SIZE | FILE_NOTIFY_CHANGE_LAST_WRITE); // watch file name changes

    if (dwChangeHandle == INVALID_HANDLE_VALUE)
    {
        PLOG_ERROR << "FindFirstChangeNotification function failed";
        ExitProcess(GetLastError());
    }

    while (TRUE)
    {
        PLOG_DEBUG << "Waiting for notification...";
        dwWaitStatus = WaitForSingleObject(dwChangeHandle, INFINITE);

        switch (dwWaitStatus)
        {
        case WAIT_OBJECT_0: // Triggered On Directory Change

            PLOG_DEBUG << "Directory Change Notification ";

            update_process_list(PProcessToBeTracked);
            if (FindNextChangeNotification(dwChangeHandle) == FALSE)
            {

                PLOG_ERROR << "FindNextChangeNotification function failed.";
                ExitProcess(GetLastError());
            }
            break;

        default:
            PLOG_ERROR << "Unhandled dwWaitStatus.";
            ExitProcess(GetLastError());
            break;
        }
    }
}
// Update the Process Tracking List After The configuration fie is modified
void update_process_list(PVOID PvOIDProcessToBeTracked)
{
    // Cast Void Pointer to ProcessToBeTracked *
    std::vector<MyProcess> *PProcessToBeTracked = (std::vector<MyProcess> *)PvOIDProcessToBeTracked;
    std::vector<MyProcess> BufVec = *PProcessToBeTracked; // Initialize a buffer vector

    PLOG_DEBUG << "Updating the existing list";
    std::vector<MyProcess> NewProcess;
    nlohmann::json data = read_config_file();
    if (!data.is_discarded()) // Check for valid json
    {
        for (auto it = data.at("processes").begin(); it != data.at("processes").end(); ++it)
        {
            std::string executable{it.value().at("exec_path")};
            std::string args{it.value().at("args")};
            char val[60];
            std::vector<MyProcess>::iterator ite;
            return_name(executable, val);
            // Check if executable name from Process List matches with the config file
            ite = std::find_if_not(BufVec.begin(), BufVec.end(), [val](MyProcess x)
                                   { return strcmp(x.name, val); });
            if (ite != BufVec.end())
            {
                PLOG_DEBUG << "Executable Name Matched "
                           << (*ite).name;
                // Check For Argument Matching if the name matches
                char arg_buf[1000];
                strcpy(arg_buf, executable.c_str());
                strcat(arg_buf, " ");
                strcat(arg_buf, args.c_str());
                if (strcmp(arg_buf, (*ite).arguments))
                {
                    MyProcess p(executable, args);
                    NewProcess.push_back(p); // Push To the list of New Processes
                    PLOG_DEBUG << "Arguments Doesn't Match, Need To Create New Process Instance" << p.arguments;
                }
                else
                {
                    PLOG_DEBUG << "Arguments Matched Too, No Need To Create New Instance";
                    BufVec.erase(ite); // Erase From Buffer Vector, Only Those removed from Config file will be in the buffer
                }
            }
            else
            {
                MyProcess p(executable, args);
                NewProcess.push_back(p); // Push To New Process List
                PLOG_DEBUG << "found New Executable " << p.name;
            }
        }

        // Remove the processes from list which are still in buffer
        for (auto i = BufVec.begin(); i != BufVec.end(); i++)
        {
            DWORD val_ppid = (*i).get_ppid();
            (*PProcessToBeTracked).erase(std::remove_if((*PProcessToBeTracked).begin(), (*PProcessToBeTracked).end(), [val_ppid](MyProcess o)
                                                        { return o.get_ppid() == val_ppid; }),
                                         (*PProcessToBeTracked).end());
        }

        // Add the new Processes added in the config file

        for (auto i = NewProcess.begin(); i != NewProcess.end(); i++)
        {
            (*PProcessToBeTracked).push_back(*i);
        }
        create_process(PProcessToBeTracked); // Create New Processes
    }
    else
    {
        PLOG_ERROR << "Corrupted JSON Data";
    }
}

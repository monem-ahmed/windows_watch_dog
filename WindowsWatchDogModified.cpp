#include <fstream>
#include "WindowsAPIHandler.h"
#include <vector>
#include <stdio.h>


int main()
{
    plog::init(plog::debug, log_file);                 // Initialize Log File
    std::vector<MyProcess> ProcessToBeTracked;         // Vector to store process Instances which need to be tracked
    nlohmann::json data = read_config_file(); // File API-read config file first
    bool read_config_status = init_processes(data, &ProcessToBeTracked);
    if (read_config_status)
        PLOG_DEBUG << "Processes Initialized";
    else
    {
        PLOG_ERROR << "Error in Processes Initialization";
    }
    bool check_status = check_existing_process(&ProcessToBeTracked);
    if (check_status)
        PLOG_DEBUG << "Successfully Checked Which Processes are running already, and opened Handles";
    else
        PLOG_ERROR << "Error in Checking Existing Processes";
    create_process(&ProcessToBeTracked);
    for (auto p = 0; p < ProcessToBeTracked.size(); ++p)
        PLOG_DEBUG << "Created/Opened Process, Name: " << ProcessToBeTracked[p].name << " ID: " << ProcessToBeTracked[p].get_ppid();

    // Start a thread for Monitoring The File
    HANDLE WatchFileThread = CreateThread(nullptr, 0, WatchFile, &ProcessToBeTracked, 0, nullptr);
    if (!WatchFileThread)
    {
        PLOG_ERROR << "Failed to create thread error=" << GetLastError();
    }

    // Periodically Monitor the processes
    while (true)
    {
        for (auto i = ProcessToBeTracked.begin(); i != ProcessToBeTracked.end(); i++)
        {
            DWORD status;
            if (GetExitCodeProcess((*i).get_handle(), &status))
                if (status != STILL_ACTIVE) // Find Out Which Processes are killed
                {
                    PLOG_WARNING << (*i).name << " Is Dead";
                    (*i).handle_created = false;
                }
        }
        create_process(&ProcessToBeTracked); // Create processes those are killed
        Sleep(periodic_check_interval);      // Monitor after interval
    }
    return 0;
}
// Reading Configuration file from ./confs/config.json


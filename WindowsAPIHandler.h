#pragma once
#include <Windows.h>
#include <winternl.h>
#include "MyProcess.h"
#include "get_cmd_line.h"
#include "MyUtility.h"
#include <TlHelp32.h>
#include "WindowsUtility.h"
#include <plog/Log.h> // Step1: include the headers
#include "plog/Initializers/RollingFileInitializer.h"

// Create Required Processes from ProcessToBeTracked Vector
void create_process(std::vector<MyProcess> *ProcessToBeTracked);
// Check which desired process are already opened and get their HANDLES
bool check_existing_process(std::vector<MyProcess> *ProcessToBeTracked);
// Get Command Line Arguments of a process
bool get_cmd_args(PROCESSENTRY32 pe, char *cmd_buf, HANDLE *hOpenProcess);
// Watch the Config Directory For any changes in config file size or lastwrite and call update_process_list
DWORD WINAPI WatchFile(PVOID);
// Update the ProcessToBeTracked List After JSON File is changed
void update_process_list(PVOID PvOIDProcessToBeTracked);
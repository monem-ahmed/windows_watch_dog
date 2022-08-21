#pragma once
#include <iostream>
#include<Windows.h>
//  Return Executable name from executable path
void return_name(std::string exec_path, char *File_Name);
// Find Current Workspace Path
std::string ExePath();
#pragma once

#include "json.hpp"
#include <fstream>
#include <iostream>
#include "MyProcess.h"
#include <plog/Log.h> // Step1: include the headers
#include "plog/Initializers/RollingFileInitializer.h"
#define conf_file ".\\confs\\config.json"
#define log_file ".\\log\\watchdog.txt"
#define periodic_check_interval 1000
// Read Config file and return JSON Object
nlohmann::json read_config_file();
// Create MyProcess Istances from config data and populate the ProcessToBeTracked Vector
bool init_processes(nlohmann::json data, std::vector<MyProcess> *ProcessToBeTracked);
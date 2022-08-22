# Windows Watchdog
An Application to monitor windows processes According to a config file. Dynamically handles changes in the config file. 
### Setup
For VSCode Setup I have followed this link: https://code.visualstudio.com/docs/cpp/config-msvc.

After Setting up VSCode To Build this code open VSCode from **Developer Command Prompt** using *code .* and select *cl.exe* as compiler.

Build all the cpp files. main.exe is our desired executable. 
### Dependencies:

1. nlohmann's json (https://github.com/nlohmann/json) library is used to parse the json. Single header ("json.hpp") is included in the repository.
2. For Logging plog by SergiusTheBest (https://github.com/SergiusTheBest/plog) is used. include folder is added in the repo.

### How To use
1. Place Configuration file in the relative directory {WorkSpaceDirectory}/confs/config.json
update the json file as per example given:
- write full path of the executable in 'exec_path' key
- write necessery command line arguments as a string

2. Create a folder named log in the relative directory {WorkSpaceDirectory}/log/
- A log file named 'watchdog.txt' will be generated and all the significant operations of the WatchDog will be documented there.

3. Run the Executable file (main.exe). Your desired apps/processes will be monitored

### Features
1. Dynamically Monitor the configuration file. Any Changes made in the config file will instsantly trigger the Watch Dog.
2. It will sync the list of the monitored process with config file.
3. In Startup the software checks for existing processes. It won't run new instances of any executable if one is already running with the desired arguments.
4. Checking for the processes is done not only by executable name but also start-up parameters.
5. This Software is portable to both 32-bit and 64-bit windows.
6. All Operations performed by the watchdog will be logged into a log file.




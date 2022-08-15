# windows_watch_dog
An Application to monitor windows processes with a dynamic config file.

## Setup
For VSCode Setup I have followed this link: https://code.visualstudio.com/docs/cpp/config-msvc

##
To compile code with VSCode open VSCode from **Developer Command Prompt** using *code .* and select *cl.exe* as compiler

#### Dependencies:

 I have Used nlohmann's json (https://github.com/nlohmann/json) library to parse the json. Single header is included in the repository

 #### Configuration File
Place Configuratio file in the relative directory ./confs/config.json
update the json file as per example given:
1. write full path of the executable
2. write necessery command line arguments as a string



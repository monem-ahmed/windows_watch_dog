#include "MyUtility.h"
#include "MyProcess.h"

nlohmann::json read_config_file()
{
    PLOG_DEBUG << "reading config file";
    std::ifstream f;
    f.open(conf_file);
    nlohmann::json data = nlohmann::json::parse(f, nullptr, false);
    return data;
}

bool init_processes(nlohmann::json data, std::vector<MyProcess> *ProcessToBeTracked)
{
    if (!data.is_discarded()) // Check if json data are valid
    {
        for (auto it = data.at("processes").begin(); it != data.at("processes").end(); ++it)
        {

            std::string executable{it.value().at("exec_path")};
            std::string args{it.value().at("args")};
            MyProcess p(executable, args);
            (*ProcessToBeTracked).push_back(p);
        }
        return true;
    }
    else
    {
        PLOG_ERROR << "Corrupted JSON Data";
        return false;
    }
}

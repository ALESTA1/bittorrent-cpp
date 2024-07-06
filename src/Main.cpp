#include <iostream>
#include <string>
#include <vector>
#include <cctype>
#include <cstdlib>
using namespace std;
#include "lib/nlohmann/json.hpp"

using json = nlohmann::json;
json decode_bencoded_value(const std::string &encoded_value, int &id);
json decodeInteger(string encoded_value, int &id)
{
    id++;
    string res = "";
    while (encoded_value[id] != 'e')
    {
        res += encoded_value[id];
        id++;
    }
    id++;
    return json(atoll(res.c_str()));
}
json decodeDictionary(string encoded_value, int &id)
{
    id++;
    json res = json::object();
    while (encoded_value[id] != 'e')
    {
        json key = decode_bencoded_value(encoded_value, id);
        json value = decode_bencoded_value(encoded_value, id);
        res[key.get<string>()] = value;
    }
    id++;
    return res;
}
json decodeList(string encoded_value, int &id)
{
    id++;
    json res = json::array();
    while (encoded_value[id] != 'e')
    {
        res.push_back(decode_bencoded_value(encoded_value, id));
    }
    id++;
    return res;
}
json decodeString(string encoded_value, int &id)
{
    string res = "";
    while (isdigit(encoded_value[id]))
    {
        res += encoded_value[id];
        id++;
    }
    int length = atoll(res.c_str());
    res = "";
    id++;
    while (length--)
    {
        res += encoded_value[id];
        id++;
    }
    return res;
}
json decode_bencoded_value(const std::string &encoded_value, int &id)
{

    if (encoded_value[id] == 'i')
    {
        return decodeInteger(encoded_value, id);
    }
    else if (encoded_value[id] == 'd')
    {
        return decodeDictionary(encoded_value, id);
    }
    else if (encoded_value[id] == 'l')
    {
        return decodeList(encoded_value, id);
    }
    else if (isdigit(encoded_value[id]))
    {
        return decodeString(encoded_value, id);
    }
    else
    {
        throw std::runtime_error("Invalid encoded value: " + encoded_value + " at index: " + to_string(id));
    }
}

int main(int argc, char *argv[])
{
    // Flush after every std::cout / std::cerr
    std::cout << std::unitbuf;
    std::cerr << std::unitbuf;

    if (argc < 2)
    {
        std::cerr << "Usage: " << argv[0] << " decode <encoded_value>" << std::endl;
        return 1;
    }

    std::string command = argv[1];

    if (command == "decode")
    {
        if (argc < 3)
        {
            std::cerr << "Usage: " << argv[0] << " decode <encoded_value>" << std::endl;
            return 1;
        }
        // You can use print statements as follows for debugging, they'll be visible when running tests.
        // std::cout << "Logs from your program will appear here!" << std::endl;

        // Uncomment this block to pass the first stage
        std::string encoded_value = argv[2];
        int id = 0;
        json decoded_value = decode_bencoded_value(encoded_value, id);
        std::cout << decoded_value.dump() << std::endl;
    }
    else
    {
        std::cerr << "unknown command: " << command << std::endl;
        return 1;
    }

    return 0;
}

#include <iostream>
#include <string>
#include <vector>
#include <cctype>
#include <cstdlib>
#include <fstream>
#include <sstream>
#include <iomanip>
#include "lib/nlohmann/json.hpp"
#include <curl/curl.h>

using json = nlohmann::json;

size_t WriteCallback(void *contents, size_t size, size_t nmemb, void *userp)
{
    ((std::string *)userp)->append((char *)contents, size * nmemb);
    return size * nmemb;
}

std::string url_encode(const std::string &str)
{
    std::string encoded_str;
    const std::string unreserved = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.~";

    for (char c : str)
    {
        if (unreserved.find(c) != std::string::npos)
        {
            encoded_str += c;
        }
        else
        {
            encoded_str += '%';
            encoded_str += "0123456789ABCDEF"[static_cast<unsigned char>(c) >> 4];
            encoded_str += "0123456789ABCDEF"[static_cast<unsigned char>(c) & 15];
        }
    }

    return encoded_str;
}

json decode_bencoded_value(const std::string &encoded_value, size_t &id);

json decodeInteger(const std::string &encoded_value, size_t &id)
{
    id++;
    std::string res = "";
    while (encoded_value[id] != 'e')
    {
        res += encoded_value[id];
        id++;
    }
    id++;
    return json(atoll(res.c_str()));
}

json decodeDictionary(const std::string &encoded_value, size_t &id)
{
    id++;
    json res = json::object();
    while (encoded_value[id] != 'e')
    {
        json key = decode_bencoded_value(encoded_value, id);
        json value = decode_bencoded_value(encoded_value, id);
        res[key.get<std::string>()] = value;
    }
    id++;
    return res;
}

json decodeList(const std::string &encoded_value, size_t &id)
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

json decodeString(const std::string &encoded_value, size_t &id)
{
    std::string res = "";
    while (isdigit(encoded_value[id]))
    {
        res += encoded_value[id];
        id++;
    }
    int length = atoi(res.c_str());
    res = "";
    id++;
    while (length--)
    {
        res += encoded_value[id];
        id++;
    }
    return res;
}

json decode_bencoded_value(const std::string &encoded_value, size_t &id)
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
        throw std::runtime_error("Invalid encoded value at index: " + std::to_string(id));
    }
}

std::string jsonToBencode(const json &value)
{
    std::string res = "";
    if (value.is_number_integer())
    {
        res += "i" + std::to_string(value.get<int>()) + "e";
    }
    else if (value.is_string())
    {
        res += std::to_string(value.get<std::string>().size()) + ":" + value.get<std::string>();
    }
    else if (value.is_array())
    {
        res += "l";
        for (auto &i : value)
        {
            res += jsonToBencode(i);
        }
        res += "e";
    }
    else if (value.is_object())
    {
        res += "d";
        for (auto &i : value.items())
        {
            res += jsonToBencode(i.key());
            res += jsonToBencode(i.value());
        }
        res += "e";
    }
    return res;
}

std::string sha1(const std::string &input)
{
    uint32_t h0 = 0x67452301;
    uint32_t h1 = 0xEFCDAB89;
    uint32_t h2 = 0x98BADCFE;
    uint32_t h3 = 0x10325476;
    uint32_t h4 = 0xC3D2E1F0;
    uint64_t bit_length = input.size() * 8;
    std::vector<uint8_t> data(input.begin(), input.end());
    data.push_back(0x80);
    while (data.size() % 64 != 56)
    {
        data.push_back(0);
    }
    for (int i = 7; i >= 0; --i)
    {
        data.push_back(bit_length >> (i * 8));
    }
    for (std::size_t i = 0; i < data.size(); i += 64)
    {
        uint32_t w[80];
        for (int j = 0; j < 16; ++j)
        {
            w[j] = (data[i + j * 4] << 24) | (data[i + j * 4 + 1] << 16) | (data[i + j * 4 + 2] << 8) | data[i + j * 4 + 3];
        }
        for (int j = 16; j < 80; ++j)
        {
            w[j] = (w[j - 3] ^ w[j - 8] ^ w[j - 14] ^ w[j - 16]);
            w[j] = (w[j] << 1) | (w[j] >> 31);
        }
        uint32_t a = h0;
        uint32_t b = h1;
        uint32_t c = h2;
        uint32_t d = h3;
        uint32_t e = h4;
        for (int j = 0; j < 80; ++j)
        {
            uint32_t f, k;
            if (j < 20)
            {
                f = (b & c) | ((~b) & d);
                k = 0x5A827999;
            }
            else if (j < 40)
            {
                f = b ^ c ^ d;
                k = 0x6ED9EBA1;
            }
            else if (j < 60)
            {
                f = (b & c) | (b & d) | (c & d);
                k = 0x8F1BBCDC;
            }
            else
            {
                f = b ^ c ^ d;
                k = 0xCA62C1D6;
            }
            uint32_t temp = ((a << 5) | (a >> 27)) + f + e + k + w[j];
            e = d;
            d = c;
            c = (b << 30) | (b >> 2);
            b = a;
            a = temp;
        }
        h0 += a;
        h1 += b;
        h2 += c;
        h3 += d;
        h4 += e;
    }
    std::ostringstream oss;
    oss << std::hex << std::setfill('0') << std::setw(8) << h0
        << std::setw(8) << h1
        << std::setw(8) << h2
        << std::setw(8) << h3
        << std::setw(8) << h4;
    return oss.str();
}

int main(int argc, char *argv[])
{
    // Flush after every std::cout / std::cerr
    std::cout << std::unitbuf;
    std::cerr << std::unitbuf;

    if (argc < 3)
    {
        std::cerr << "Usage: " << argv[0] << " <command> <file_path or encoded_value>" << std::endl;
        return 1;
    }

    std::string command = argv[1];

    if (command == "decode")
    {
        std::string encoded_value = argv[2];
        size_t id = 0;
        try
        {
            json decoded_value = decode_bencoded_value(encoded_value, id);
            std::cout << decoded_value.dump() << std::endl;
        }
        catch (const std::exception &e)
        {
            std::cerr << "Decode error: " << e.what() << std::endl;
            return 1;
        }
    }
    else if (command == "info" || command == "peers")
    {
        std::string filePath = argv[2];
        std::ifstream file(filePath, std::ios::binary);
        if (!file.is_open())
        {
            std::cerr << "Failed to open file: " << filePath << std::endl;
            return 1;
        }
        std::stringstream buffer;
        buffer << file.rdbuf();
        std::string fileContent = buffer.str();

        try
        {
            size_t id = 0;
            json decoded_value = decode_bencoded_value(fileContent, id);
            if (command == "info")
            {
                std::cout << "Tracker URL: " << decoded_value["announce"].get<std::string>() << std::endl;
                std::cout << "Length: " << decoded_value["info"]["length"].get<int>() << std::endl;

                std::string bencodedInfo = jsonToBencode(decoded_value["info"]);
                std::string infoHash = sha1(bencodedInfo);
                std::cout << "Info Hash: ";
                for (char c : infoHash)
                {
                    std::cout << std::hex << std::setw(2) << std::setfill('0') << (static_cast<int>(c) & 0xff);
                }
                std::cout << std::endl;

                int pieceLength = decoded_value["info"]["piece length"].get<int>();
                std::cout << "Piece Length: " << pieceLength << std::endl;

                std::string pieces = decoded_value["info"]["pieces"].get<std::string>();
                std::cout << "Piece Hashes: " << std::endl;
                for (size_t i = 0; i < pieces.size(); i += 20)
                {
                    std::stringstream ss;
                    for (size_t j = 0; j < 20; ++j)
                    {
                        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(pieces[i + j]);
                    }
                    std::cout << ss.str() << std::endl;
                }
            }
            else if (command == "peers")
            {
                std::string trackerURL = decoded_value["announce"].get<std::string>();
                std::string infoHash = sha1(jsonToBencode(decoded_value["info"]));
                std::string peerId = "00112233445566778899"; // Replace with your own peer ID
                int port = 6881;                             // Replace with your port
                int uploaded = 0;
                int downloaded = 0;
                int left = decoded_value["info"]["length"].get<int>();

                std::string query = "?info_hash=" + url_encode(infoHash) +
                                    "&peer_id=" + url_encode(peerId) +
                                    "&port=" + std::to_string(port) +
                                    "&uploaded=" + std::to_string(uploaded) +
                                    "&downloaded=" + std::to_string(downloaded) +
                                    "&left=" + std::to_string(left) +
                                    "&compact=1";

                std::string trackerResponse;
                CURL *curl = curl_easy_init();
                if (curl)
                {
                    std::string trackerURLWithQuery = trackerURL + query;
                    curl_easy_setopt(curl, CURLOPT_URL, trackerURLWithQuery.c_str());
                    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
                    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &trackerResponse);
                    CURLcode res = curl_easy_perform(curl);
                    if (res != CURLE_OK)
                    {
                        std::cerr << "Failed to make a request to the tracker: " << curl_easy_strerror(res) << std::endl;
                        curl_easy_cleanup(curl);
                        return 1;
                    }
                    curl_easy_cleanup(curl);
                }
                else
                {
                    std::cerr << "Failed to initialize CURL." << std::endl;
                    return 1;
                }

                try
                {
                    size_t id = 0;
                    json trackerResponseJson = decode_bencoded_value(trackerResponse, id);
                    std::string peers = trackerResponseJson["peers"].get<std::string>();
                    std::cout << "Peers: " << std::endl;
                    for (size_t i = 0; i < peers.size(); i += 6)
                    {
                        std::string peerIP = std::to_string(static_cast<unsigned char>(peers[i])) + "." +
                                             std::to_string(static_cast<unsigned char>(peers[i + 1])) + "." +
                                             std::to_string(static_cast<unsigned char>(peers[i + 2])) + "." +
                                             std::to_string(static_cast<unsigned char>(peers[i + 3]));
                        int peerPort = (static_cast<unsigned char>(peers[i + 4]) << 8) + static_cast<unsigned char>(peers[i + 5]);
                        std::cout << peerIP << ":" << peerPort << std::endl;
                    }
                }
                catch (const std::exception &e)
                {
                    std::cerr << "Error decoding tracker response: " << e.what() << std::endl;
                    return 1;
                }
            }
        }
        catch (const std::exception &e)
        {
            std::cerr << "Decode error: " << e.what() << std::endl;
            return 1;
        }
    }
    else
    {
        std::cerr << "Unknown command: " << command << std::endl;
        return 1;
    }

    return 0;
}

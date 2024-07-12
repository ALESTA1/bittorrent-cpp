#include <iostream>
#include <string>
#include <vector>
#include <cctype>
#include <cstdlib>
#include <fstream>
#include <sstream>
using namespace std;
#include "lib/nlohmann/json.hpp"
#include <curl/curl.h>
using json = nlohmann::json;
size_t WriteCallback(void *contents, size_t size, size_t nmemb, void *userp)
{
    ((std::string *)userp)->append((char *)contents, size * nmemb);
    return size * nmemb;
}
std::string url_encode(const std::string& str) {
    std::string encoded_str;
    const std::string unreserved = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.~";
    
    for (char c : str) {
        if (unreserved.find(c) != std::string::npos) {
            encoded_str += c;
        } else {
            encoded_str += '%';
            encoded_str += "0123456789ABCDEF"[static_cast<unsigned char>(c) >> 4];
            encoded_str += "0123456789ABCDEF"[static_cast<unsigned char>(c) & 15];
        }
    }
    
    return encoded_str;
}
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
string jsonToBencode(json value)
{
    string res = "";
    if (value.is_number_integer())
    {
        res += "i" + to_string(value.get<int>()) + "e";
    }
    else if (value.is_string())
    {
        res += to_string(value.get<string>().size()) + ":" + value.get<string>();
    }
    else if (value.is_array())
    {
        res += "l";
        for (auto i : value)
        {
            res += jsonToBencode(i);
        }
        res += "e";
    }
    else if (value.is_object())
    {
        res += "d";
        for (auto i : value.items())
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
    // testing stage 44
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
    else if (command == "info")
    {
        std::string filePath = argv[2];
        std::ifstream file(filePath, std::ios::binary);
        std::string fileContent((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
        file.close();
        int id = 0;
        json decoded_value = decode_bencoded_value(fileContent, id);
        cout << "Tracker URL: " << decoded_value["announce"].get<string>() << endl;
        cout << "Length: " << decoded_value["info"]["length"].get<int>() << endl;
        string bencodedInfo = jsonToBencode(decoded_value["info"]);
        string infoHash = sha1(bencodedInfo);
        cout << "Info Hash: " << infoHash << endl;
        int pieceLength = decoded_value["info"]["piece length"].get<int>();
        cout << "Piece Length: " << pieceLength << endl;
        string pieces = decoded_value["info"]["pieces"].get<string>();

        cout << "Piece Hashes: " << endl;
        for (int i = 0; i < pieces.size(); i += 20)
        {
            std::string single_piece = decoded_value["info"]["pieces"].get<std::string>().substr(i, 20);
            std::stringstream ss;
            for (unsigned char byte : single_piece)
            {
                ss << std::hex << std::setw(2) << std::setfill('0') << (int)byte;
            }
            std::cout << ss.str() << std::endl;
        }
    }
    else if (command == "peers")
    {
        // Extract the necessary information for the tracker request
        std::string filePath = argv[2];
        std::ifstream file(filePath, std::ios::binary);
        std::string fileContent((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
        file.close();
        int id = 0;
        json decoded_value = decode_bencoded_value(fileContent, id);
        std::string trackerURL = decoded_value["announce"].get<std::string>();
        std::string infoHash = infoHash;
        std::string peerId = "00112233445566778899";
        int port = 6881;
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

        // Make the GET request to the tracker
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
                return 1;
            }
            curl_easy_cleanup(curl);
        }

        // Parse the tracker response
        id = 0;
        json trackerResponseJson = decode_bencoded_value(trackerResponse, id);
        std::string peers = trackerResponseJson["peers"].get<std::string>();

        // Process the list of peers
        for (int i = 0; i < peers.size(); i += 6)
        {
            std::string peerIP = std::to_string((unsigned char)peers[i]) + "." +
                                 std::to_string((unsigned char)peers[i + 1]) + "." +
                                 std::to_string((unsigned char)peers[i + 2]) + "." +
                                 std::to_string((unsigned char)peers[i + 3]);
            int peerPort = (unsigned char)peers[i + 4] * 256 + (unsigned char)peers[i + 5];
            std::cout << peerIP << ":" << peerPort << std::endl;
        }
    }
    else
    {
        std::cerr << "unknown command: " << command << std::endl;
        return 1;
    }

    return 0;
}

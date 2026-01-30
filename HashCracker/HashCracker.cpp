#include <iostream>
#include <fstream>
#include <string>
#include <openssl/evp.h>
#include <iomanip>
#include <sstream>



//function to hash the string value
void hashString(EVP_MD_CTX* ctx,
                const EVP_MD* md,
                const std::string& input,
                unsigned char* out,
                unsigned int& outLen)
{
    EVP_DigestInit_ex(ctx, md, nullptr);
    EVP_DigestUpdate(ctx, input.data(), input.size());
    EVP_DigestFinal_ex(ctx, out, &outLen);
}

std::string toHex(const unsigned char* data, unsigned int len) {
    std::ostringstream oss;
    for (unsigned int i = 0; i < len; i++) {
        oss << std::hex << std::setw(2) << std::setfill('0')
    << static_cast<int>(data[i]);

    }
    return oss.str();
}


int main() {


    std::string filePath;
    std::string algorithmName;
    std::string hashValue;
    int hashType;

    const EVP_MD* md = nullptr;
    std::fstream file;
    unsigned char digest[EVP_MAX_MD_SIZE];


    // User inputs
    std::cout << "Please enter the hash that you want to bruteforce:" << std::endl;
    std::cin >> hashValue; // target hash that we will try to match
    std::cout << "Please enter the file path to the world list: " << std::endl;
    std::cin >> filePath; // path to wordlist file
    std::cout << "Please enter the algorithm:\n " << "1: Sha1\n 2: Sha256\n 3: Sha512 "<< std::endl;


    // rithm selection loop
    while (true){
        bool valid = false;
        std::cin >> hashType;
        switch (hashType) {
            case 1 : algorithmName = "Sha1";valid = true;md = EVP_sha1();break;
            case 2 : algorithmName = "Sha256";valid = true;md = EVP_sha256();break;
            case 3 : algorithmName = "Sha512";valid = true;md = EVP_sha512();break;
            default : std::cout << "Invalid choice please try again: "<< std::endl;valid=false;break;
        }
        if (valid) break; // exit loop if user chose valid 
    }
    std::cout <<"Selected algorithm: "<< algorithmName << std::endl;
    file.open(filePath, std::ios::in );
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        std::cerr << "Failed to create EVP_MD_CTX\n";
        return 1;
    }
    if (!file) {
        std::cerr << "Error: Could not open world list file: " << filePath << std::endl;
        EVP_MD_CTX_free(ctx);
        return 1;
    }
    if (file.is_open()) {
        bool found = false;
        unsigned int length;
        std::string line;

        // Read each line from wordlist and hash it
        // Compare binary hash converted to hex with target hash
        while (std::getline(file, line)) {
            hashString(ctx, md, line, digest, length);
            if (toHex(digest, length) == hashValue) {
                std::cout << "Text value of the hash found: "<< line << std::endl;
                found = true;
                break;
            }
        }
        EVP_MD_CTX_free(ctx);
        if (!found) {
            std::cout << "text value of the hash could not be found!" << std::endl;
        }
    }
    return 0;

}
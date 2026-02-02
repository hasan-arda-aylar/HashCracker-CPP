#include <iostream>
#include <fstream>
#include <string>
#include <openssl/evp.h>
#include <iomanip>
#include <sstream>
#include <algorithm>
#include <cctype>




// Function to compute the hash of the input string using the specified algorithm
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

// Function to convert a byte array to a hex string
std::string toHex(const unsigned char* data, unsigned int len) {
    std::ostringstream oss;
    for (unsigned int i = 0; i < len; i++) {
        oss << std::hex << std::setw(2) << std::setfill('0')
    << static_cast<int>(data[i]);

    }
    return oss.str();
}

// Function to convert a string to lowercase
void toLowerCase(std::string& s) {
    std::transform(
        s.begin(),
        s.end(),
        s.begin(),
        [](unsigned char c) {
            return std::tolower(c);
        }
    );
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
    toLowerCase(hashValue); // Convert the input hash to lowercase to ensure consistent comparison
    std::cout << "Please enter the file path to the world list: " << std::endl;
    std::cin >> filePath; // path to wordlist file
    std::cout << "Supported algorithms :\n " << "1: MD5\n 2: Ripmed-160\n 3: Sha1\n 4: Sha224\n 5: Ripmed-160\n "
    "6: Sha-384\n 7: Sha-512\n Please make an selection :\n"<< std::endl;


    // algorithm selection loop
    while (true){
        bool valid = false;
        std::cin >> hashType;
        switch (hashType) {
            case 1 : algorithmName = "MD5";valid = true;md = EVP_md5();break;
            case 2 : algorithmName = "Ripemd-160";valid = true;md = EVP_ripemd160();break;
            case 3 : algorithmName = "Sha1";valid = true;md = EVP_sha1();break;
            case 4 : algorithmName = "Sha224";valid = true;md = EVP_sha224();break;
            case 5 : algorithmName = "Sha256";valid = true;md = EVP_sha256();break;
            case 6 : algorithmName = "Sha384";valid = true;md = EVP_sha384();break;
            case 7 : algorithmName = "Sha512";valid = true;md = EVP_sha512();break;
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
        file.close();
        if (!found) {
            std::cout << "text value of the hash could not be found!" << std::endl;
        }
    }
    return 0;

}

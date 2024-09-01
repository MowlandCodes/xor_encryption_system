// Coloring text in the console
#define RESET   "\x1b[0m"
#define RED     "\x1b[31m"
#define GREEN   "\x1b[32m"
#define YELLOW  "\x1b[33m"
#define BLUE    "\x1b[37m"
#define BOLD    "\x1b[1m"

#include <algorithm>
#include <cstdint>
#include <fstream>
#include <filesystem>
#include <iostream>
#include <iterator>
#include <string>
#include <sstream>
#include <iomanip>
#include <vector>
#include <Windows.h>
#include <openssl/sha.h> // 32-bit SHA-256 hash function
#include <openssl/evp.h> // 32-bit SHA-256 hash function

namespace file_sys = std::filesystem;
using namespace std;


// This function is used to calculate the checksum of the data to prevent data tampering and to prevent incorrect decryption
void calculate_checksum_and_save(const string &filename, const string &checksum_file){
    ifstream input_file(file_sys::absolute(filename), ios::binary);
    ofstream output_file(file_sys::absolute(checksum_file), ios::binary);

    if (!input_file){
        cerr << RED << BOLD << "\n[!]" << RESET << " Error opening file" << endl;
    }

    EVP_MD_CTX *context = EVP_MD_CTX_new();

    if(!context){
        cerr << RED << BOLD << "\n[!]" << RESET << " Error creating EVP context" << endl;
        return;
    }

    if(EVP_DigestInit_ex(context, EVP_sha256(), nullptr) != 1){
        cerr << RED << BOLD << "\n[!]" << RESET << " Error initializing SHA256 context" << endl;
        EVP_MD_CTX_free(context);
        return;
    }

    const size_t CHUNK_SIZE = 1024 * 1024; // 1 MB
    vector<char> buffer(CHUNK_SIZE);

    while (input_file){
        input_file.read(buffer.data(), CHUNK_SIZE);
        size_t bytes_read = input_file.gcount();
        if(EVP_DigestUpdate(context, buffer.data(), bytes_read) != 1){
            cerr << RED << BOLD << "\n[!]" << RESET << " Error updating digest" << endl;
            EVP_MD_CTX_free(context);
            return;
        }
    }

    unsigned char hash[SHA256_DIGEST_LENGTH];
    unsigned int hash_length = 0;

    if (EVP_DigestFinal_ex(context, hash, &hash_length) != 1){
        cerr << RED << BOLD << "\n[!]" << RESET << " Error finalizing digest" << endl;
        EVP_MD_CTX_free(context);
        return;
    }

    EVP_MD_CTX_free(context);

    if (!output_file){
        cerr << RED << BOLD << "\n[!]" << RESET << " Error opening checksum destination file" << endl;
    }

    stringstream hash_stream;

    for(unsigned int i = 0; i < hash_length; i++){
        hash_stream << hex << setw(2) << setfill('0') << (int)hash[i];
    }

    output_file << hash_stream.str();
    output_file.close();
}

// This function is used to verify the checksum of a file
bool verify_checksum(const file_sys::path &file_to_check, const file_sys::path &checksum_filename){
    // Variables Initialization
    ifstream file_check(file_sys::absolute(file_to_check), ios::binary), checksum_file(file_sys::absolute(checksum_filename), ios::binary);
    stringstream checksum_stream, file_stream;
    string checksum_str, file_str;
    unsigned char file_hash[SHA256_DIGEST_LENGTH];
    unsigned int hash_length = 0;

    // Checking the checksum file
    if (!checksum_file){
        cout << file_sys::absolute(checksum_filename);
        cerr << RED << BOLD << "\n[!]" << RESET << " Error opening checksum file" << endl;
        return false;
    }

    // Checking the file to check
    if (!file_check){
        cerr << RED << BOLD << "\n[!]" << RESET << " Error opening file to check" << endl;
        return false;
    }

    // Initializing 32-bit SHA-256 hash function to check the checksum
    EVP_MD_CTX *context = EVP_MD_CTX_new();

    if (!context){
        cerr << RED << BOLD << "\n[!]" << RESET << " Error creating EVP context" << endl;
        return false;
    }

    if (EVP_DigestInit_ex(context, EVP_sha256(), nullptr) != 1){
        cerr << RED << BOLD << "\n[!]" << RESET << " Error initializing SHA256 context" << endl;
        EVP_MD_CTX_free(context);
        return false;
    }

    const size_t CHUNK_SIZE = 1024 * 1024; // 1 MB
    vector<char> buffer(CHUNK_SIZE);

    while (file_check){
        file_check.read(buffer.data(), CHUNK_SIZE);
        size_t bytes_read = file_check.gcount();
        if (EVP_DigestUpdate(context, buffer.data(), bytes_read) != 1){
            cerr << RED << BOLD << "\n[!]" << RESET << " Error updating digest" << endl;
            EVP_MD_CTX_free(context);
            return false;
        }
    }


    if (EVP_DigestFinal_ex(context, file_hash, &hash_length) != 1){
        cerr << RED << BOLD << "\n[!]" << RESET << " Error finalizing digest" << endl;
        EVP_MD_CTX_free(context);
        return false;
    }

    // Freeing the memory from the SHA256 hash context and closing the file
    EVP_MD_CTX_free(context);
    file_check.close();

    // Reading the checksum file
    checksum_stream << checksum_file.rdbuf();
    checksum_str = checksum_stream.str();

    // Converting the file_hash into string
    for (unsigned int i = 0; i < hash_length; i++){
        file_stream << hex << setw(2) << setfill('0') << (int)file_hash[i];
    }

    file_str = file_stream.str();

    // // Comparing the checksum
    // std::cout << "File to check's checksums : " << file_str << endl;
    // std::cout << "Checksum file's checksums : " << checksum_str << endl;

    if (checksum_str == file_str){
        return true;
    } else {
        return false;
    }

}


// This function is used to separate the file name and the extension
pair<string, string> separate_file_name_and_extension(const string &file_name) {
    int dot_position = file_name.find_last_of('.');

    if (dot_position == string::npos) {
        return make_pair(file_name, "");
    }

    string file_name_without_extension = file_name.substr(0, dot_position);
    string file_extension = file_name.substr(dot_position + 1);
    return make_pair(file_name_without_extension, file_extension);
}

// This function is used to get the terminal width
int get_terminal_width() {
    CONSOLE_SCREEN_BUFFER_INFO csbi;
    int columns;

    GetConsoleScreenBufferInfo(GetStdHandle(STD_OUTPUT_HANDLE), &csbi);
    columns = csbi.srWindow.Right - csbi.srWindow.Left + 1;
    return columns;
}


// This function is used to split several files that splitted by comma
vector<string> split_delimiter(const string &s, char delimiter) {
    vector<string> tokens;
    string token;

    std::istringstream tokenStream(s);

    while (std::getline(tokenStream, token, delimiter)) {
        tokens.push_back(token);
    }

    return tokens;
}

// Main function for encrypting the file using XOR encryption
void encrypt_file(const file_sys::path &file_to_encrypt, const string &password) {
    const size_t CHUNK_SIZE = 1024 * 1024; // 1 MB
    vector<char> buffer(CHUNK_SIZE);
    int password_position = 0;
    ifstream file(file_sys::absolute(file_to_encrypt.string()), ios::binary);
    ofstream temp_file(file_sys::absolute(file_to_encrypt.string() + ".encrypted"), ios::binary);

    if (!file.is_open()) {
        cerr << RED << BOLD << "\n[!]" << RESET << " Error opening file to encrypt" << endl;
        return;
    }

    if (!temp_file.is_open()) {
        cerr << RED << BOLD << "\n[!]" << RESET << " Error opening temp file" << endl;
        return;
    }

    if (file_sys::absolute(file_to_encrypt.filename().string()) == file_sys::absolute(__FILE__)) {
        cerr << RED << BOLD << "\n[!]" << RESET << " You cannot encrypt this file" << endl;
        return;
    }

    file_sys::path checksum_path = file_sys::absolute(file_to_encrypt.string() + ".checksum");
    calculate_checksum_and_save(file_to_encrypt.string(), checksum_path.string());

    try {
        while (file){
            file.read(buffer.data(), CHUNK_SIZE);
            size_t bytes_read = file.gcount();

            for (size_t i = 0; i < bytes_read; i++) {
                buffer[i] ^= password[password_position];
                password_position = (password_position + 1) % password.length();
            }

            temp_file.write(buffer.data(), bytes_read);
        }
        temp_file.close();
        file.close();
        remove(file_sys::absolute(file_to_encrypt.string().c_str()));

        cout << GREEN << BOLD << "\n[!]" << RESET << " File encrypted successfully" << endl;
    } catch (const exception &e) {
        cerr << RED << BOLD << "\n[!]" << RESET << " Error encrypting file\n" << e.what() << endl;
    }

}


// Main function for decrypting the file using XOR decryption
void decrypt_file(const file_sys::path &file_to_decrypt, const string &password) {
    const size_t CHUNK_SIZE = 1024 * 1024; // 1 MB Chunk
    vector<char> buffer(CHUNK_SIZE);
    int password_position = 0;
    ifstream file(file_sys::absolute(file_to_decrypt.string()), ios::binary);
    ofstream temp_file(file_sys::absolute(file_to_decrypt).parent_path() / "temp", ios::binary);

    auto [file_name, file_extension] = separate_file_name_and_extension(file_to_decrypt.filename().string());
    auto [real_file_name, real_file_extension] = separate_file_name_and_extension(file_name);

    file_sys::path checksum_path = file_sys::absolute(file_to_decrypt).parent_path() / (real_file_name + "." + real_file_extension + ".checksum");

    if (!file.is_open()) {
        cerr << RED << BOLD << "\n[!]" << RESET << " Error opening file to decrypt" << endl;
        return;
    }

    if (!temp_file.is_open()) {
        cerr << RED << BOLD << "\n[!]" << RESET << " Error opening temp file" << endl;
        return;
    }

    try {
        while (file) {
            file.read(buffer.data(), CHUNK_SIZE);
            size_t bytes_read = file.gcount();

            for (size_t i = 0; i < bytes_read; i++) {
                buffer[i] ^= password[password_position];
                password_position = (password_position + 1) % password.length();
            }
            temp_file.write(buffer.data(), bytes_read);
        }

        file.close();
        temp_file.close();

        if (verify_checksum(file_sys::absolute(file_to_decrypt.string()).parent_path() / "temp", checksum_path)) {
            cout << GREEN << BOLD << "\n[+]" << RESET << " File decrypted successfully" << endl;
            remove(file_sys::absolute(file_to_decrypt.string()));
            remove(file_sys::absolute(file_to_decrypt).parent_path() / (real_file_name + "." + real_file_extension + ".checksum"));
            rename(file_sys::absolute(file_to_decrypt).parent_path() / "temp", file_sys::absolute(file_to_decrypt).parent_path() / (real_file_name + "." + real_file_extension));
        } else {
            cerr << RED << BOLD << "\n[!]" << RESET << " Checksum verification failed" << endl;
            remove(file_sys::absolute(file_to_decrypt).parent_path() / "temp");
        }
    } catch (const exception &e) {
        cerr << RED << BOLD << "\n[!]" << RESET << " Error decrypting file\n" << e.what() << endl;
        return;
    }

}

void encrypt_directory(const file_sys::path &directory_to_encrypt, const string &password) {
    for (const auto &entry : file_sys::recursive_directory_iterator(directory_to_encrypt)) {
        if (file_sys::is_regular_file(entry)) {
            encrypt_file(entry, password);
        }
    }
}

void decrypt_directory(const file_sys::path &directory_to_decrypt, const string &password) {
    for (const auto &entry : file_sys::recursive_directory_iterator(directory_to_decrypt)) {
        if (file_sys::is_regular_file(entry)) {
            string filename = entry.path().filename().string();
            if (filename.length() >= 10 && filename.substr(filename.length() - 10) == ".encrypted") {
                decrypt_file(entry, password);
            }
        }
    }
}

void print_centered(const string &text) {
    int terminal_width = get_terminal_width();
    int text_length = text.length();
    int padding = (terminal_width - text_length) / 2;

    std::cout << string(padding, ' ') << text << endl;
}

string to_lowercase(string &input) {
    for (char &c : input) {
        c = tolower(c);
    }

    return input;
}

int main(int argc, char *argv[]) {
    vector<string> list_of_files;
    string file_name, dir_name, password;
    int option;
    int terminal_width = get_terminal_width();

    std::cout << GREEN << BOLD << string(terminal_width, '=') << RESET << endl;
    std::cout << GREEN;
    print_centered("File Encryptor 1.0");
    std::cout << GREEN << BOLD << string(terminal_width, '=') << RESET << endl;

    bool repeat = false;
    do {
        std::cout << YELLOW << BOLD << "\nChoose your option :\n" << RESET << endl;
        std::cout << "[1] Encrypt File(s)" << endl;
        std::cout << "[2] Encrypt Directory" << endl;
        std::cout << "[3] Decrypt File(s)" << endl;
        std::cout << "[4] Decrypt Directory" << endl;
        std::cout << "[5] Exit" << endl;

        std::cout << YELLOW << BOLD <<"\n[?] Enter your option : " << RESET << BOLD;

        // Getting the user's input
        Sleep(1000);
        char ch;
        while (std::cin.get(ch)) {
            if (ch == '\n') {
                break;
            }

            option = ch - '0';
        }

        switch(option){
            case 1:
                std::cout << "Enter file(s) name [separated by comma (,)] : ";
                std::getline(std::cin, file_name);
                std::cout << "\nEnter password to encrypt file(s) (You must keep this password safe in order to decrypt the file(s)) : ";
                std::getline(std::cin, password);
                std::cout << endl;

                if(file_name.empty() || password.empty()) {
                    std::cout << "\x1b[37;41m" << BOLD << "\nInvalid input\n\x1b[0;33mQUITTING" << RESET << endl;
                    return 0;
                } else if(file_name.find(',') == string::npos) {
                    std::cout << endl << YELLOW << "[+]" << RESET << " Encrypting file..." << endl;
                    try {
                        // Encrypting the file
                        encrypt_file(file_sys::path(file_name), password);
                    } catch(const std::exception& e){
                        std::cerr << e.what() << '\n';
                    }
                } else {
                    // Splitting the file name
                    list_of_files = split_delimiter(file_name, ',');

                    // Processing the file name to encrypt
                    std::cout << endl << YELLOW << "[+]" << RESET << " Encrypting file(s)..." << endl;
                    for (const auto &file : list_of_files) {
                        try{
                            encrypt_file(file_sys::path(file), password);
                        } catch(const std::exception& e){
                            std::cerr << e.what() << '\n';
                        }
                    }
                }

                break;

            case 2:
                std::cout << "Enter directory name : ";
                std::getline(std::cin, dir_name);
                std::cout << "\nEnter password to encrypt directory (You must keep this password safe in order to decrypt the directory) : ";
                std::getline(std::cin, password);

                if(dir_name.empty() || password.empty()) {
                    std::cout << "\x1b[37;41m" << BOLD << "\nInvalid input\n\x1b[0;33mQUITTING" << RESET << endl;
                    return 0;

                } else if(file_sys::exists(dir_name) && file_sys::is_directory(dir_name)) {
                    std::cout << endl << YELLOW << "[+]" << RESET << " Encrypting directory..." << endl;
                    try {
                        // Encrypting the directory
                        encrypt_directory(file_sys::path(dir_name), password);
                    } catch(const std::exception& e){
                        std::cerr << e.what() << '\n';
                    }
                } else {
                    std::cout << "\x1b[37;41m" << BOLD << "\nInvalid input\n\x1b[0;33mQUITTING" << RESET << endl;
                    return 0;
                }
                break;

            case 3:
                std::cout << "Enter file(s) name [separated by comma (,)] : ";
                std::getline(std::cin, file_name);
                std::cout << "Enter password to decrypt file(s) : ";
                std::getline(std::cin, password);
                std::cout << endl;

                if(file_name.empty() || password.empty()) {
                    std::cout << "\x1b[37;41m" << BOLD << "\nInvalid input\n\x1b[0;33mQUITTING" << RESET << endl;
                    return 0;

                } else if(file_name.find(',') == string::npos) {
                    std::cout << endl << YELLOW << "[+]" << RESET << " Decrypting file..." << endl;
                    try {
                        // Decrypting the file
                        decrypt_file(file_sys::path(file_name), password);
                    } catch(const std::exception& e){
                        std::cerr << e.what() << '\n';
                    }

                } else {
                    // Splitting the file name
                    list_of_files = split_delimiter(file_name, ',');

                    // Processing the file name to decrypt
                    std::cout << endl << YELLOW << "[+]" << RESET << " Decrypting file(s)..." << endl;
                    for (const auto &file : list_of_files) {
                        try{
                            decrypt_file(file_sys::path(file), password);
                        } catch(const std::exception& e){
                            std::cerr << e.what() << '\n';
                        }
                    }
                }
                break;

            case 4:
                std::cout << "Enter directory name : ";
                std::getline(std::cin, dir_name);
                std::cout << "\nEnter password to decrypt directory : ";
                std::getline(std::cin, password);

                if(dir_name.empty() || password.empty()) {
                    std::cout << "\x1b[37;41m" << BOLD << "\nInvalid input\n\x1b[0;33mQUITTING" << RESET << endl;
                    return 0;

                } else if(file_sys::exists(dir_name) && file_sys::is_directory(dir_name)) {
                    std::cout << endl << YELLOW << "[+]" << RESET << " Decrypting directory..." << endl;
                    try {
                        // Decrypting the directory
                        decrypt_directory(file_sys::path(dir_name), password);
                    } catch(const std::exception& e){
                        std::cerr << e.what() << '\n';
                    }
                } else {
                    std::cout << "\x1b[37;41m" << BOLD << "\nInvalid input\n\x1b[0;33mQUITTING" << RESET << endl;
                    return 0;
                }
                break;

            case 5:
                std::cout << "\x1b[37;41m" << BOLD << "\nExiting..." << RESET << endl;
                return 0;
                break;

            default:
                std::cout << "\x1b[37;41m" << BOLD << "\nInvalid option\n\n\x1b[0;33mQUITTING" << RESET << endl;
                break;
        }

        string is_repeat;
        std::cout << YELLOW << "\n[+]" << RESET << " Do you want to continue? [y/n] : ";
        std::cin >> is_repeat;
        std::cin.ignore();

        if (to_lowercase(is_repeat) == "y") {
            repeat = true;
        } else {
            repeat = false;
        }

    } while(repeat == true);

    return 0;
}
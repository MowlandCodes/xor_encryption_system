# 🔐 XOR File Encryption System

## 🌟 Features

- 🔒 Encrypt single files or entire directories
- 🔓 Decrypt single files or entire directories
- 🔑 Password-based encryption using XOR cipher
- ✅ Checksum verification to ensure data integrity
- 🚀 Fast processing with 1MB chunk size
- 🎨 Colorful console output for better user experience

## 🛠️ Technologies Used

- C++17
- OpenSSL (for SHA-256 hashing)
- Windows API (for console manipulation)

## 🚀 Getting Started

### Prerequisites

- C++17 compatible compiler
- OpenSSL library
- Windows OS (for console color support)

### Compilation

Compile the program using your preferred C++ compiler. Make sure to link against the OpenSSL library.

Example using g++:

```bash
g++ -std=c++17 file_encryptor.cpp -o file_encryptor -lssl -lcrypto
```

### Running the Program

To run the program, execute the compiled binary using this command :

```bash
./file_encryptor
```

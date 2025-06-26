#ifndef DES_H
#define DES_H

#include <string>

void des_encrypt_file(const std::string& inFile, const std::string& outFile, const std::string& hexKey);
void des_decrypt_file(const std::string& inFile, const std::string& outFile, const std::string& hexKey);

#endif
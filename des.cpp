#include "des.h"
#include <openssl/des.h>
#include <fstream>
#include <vector>
#include <iostream>
#include <stdexcept>
#include <cstring>

static void pkcs5_pad(std::vector<unsigned char>& data) {
    size_t pad_len = 8 - (data.size() % 8);
    data.insert(data.end(), pad_len, static_cast<unsigned char>(pad_len));
}

static void pkcs5_unpad(std::vector<unsigned char>& data) {
    if (data.empty()) return;
    unsigned char pad_len = data.back();
    if (pad_len < 1 || pad_len > 8) return; 
    for (size_t i = data.size() - pad_len; i < data.size(); ++i) {
        if (data[i] != pad_len) return; 
    }
    data.resize(data.size() - pad_len);
}

void des_encrypt_file(const std::string& inFile, const std::string& outFile, const std::string& hexKey) {
    if (hexKey.size() != 16)
        throw std::runtime_error("DES密钥必须为16个十六进制字符(8字节)");

   
    DES_cblock key;
    for (int i = 0; i < 8; ++i) {
        std::string byteStr = hexKey.substr(i * 2, 2);
        key[i] = static_cast<unsigned char>(std::stoul(byteStr, nullptr, 16));
    }

    DES_key_schedule schedule;
    DES_set_key_unchecked(&key, &schedule);


    std::ifstream fin(inFile, std::ios::binary);
    if (!fin) throw std::runtime_error("无法打开输入文件");

    std::vector<unsigned char> buffer((std::istreambuf_iterator<char>(fin)), {});
    fin.close();

   
    pkcs5_pad(buffer);

    std::ofstream fout(outFile, std::ios::binary);
    if (!fout) throw std::runtime_error("无法创建输出文件");

 
    for (size_t i = 0; i < buffer.size(); i += 8) {
        DES_cblock inputBlock, outputBlock;
        memcpy(inputBlock, &buffer[i], 8);
        DES_ecb_encrypt(&inputBlock, &outputBlock, &schedule, DES_ENCRYPT);
        fout.write(reinterpret_cast<char*>(outputBlock), 8);
    }

    fout.close();
}

void des_decrypt_file(const std::string& inFile, const std::string& outFile, const std::string& hexKey) {
    if (hexKey.size() != 16)
        throw std::runtime_error("DES密钥必须为16个十六进制字符(8字节)");

  
    DES_cblock key;
    for (int i = 0; i < 8; ++i) {
        std::string byteStr = hexKey.substr(i * 2, 2);
        key[i] = static_cast<unsigned char>(std::stoul(byteStr, nullptr, 16));
    }

    DES_key_schedule schedule;
    DES_set_key_unchecked(&key, &schedule);

    std::ifstream fin(inFile, std::ios::binary);
    if (!fin) throw std::runtime_error("无法打开输入文件");

    std::vector<unsigned char> buffer((std::istreambuf_iterator<char>(fin)), {});
    fin.close();

    if (buffer.size() % 8 != 0)
        throw std::runtime_error("输入文件大小不是8字节的整数倍");

  
    for (size_t i = 0; i < buffer.size(); i += 8) {
        DES_cblock inputBlock, outputBlock;
        memcpy(inputBlock, &buffer[i], 8);
        DES_ecb_encrypt(&inputBlock, &outputBlock, &schedule, DES_DECRYPT);
        memcpy(&buffer[i], outputBlock, 8);
    }

 
    pkcs5_unpad(buffer);

    std::ofstream fout(outFile, std::ios::binary);
    if (!fout) throw std::runtime_error("无法创建输出文件");

    fout.write(reinterpret_cast<char*>(buffer.data()), buffer.size());
    fout.close();
}
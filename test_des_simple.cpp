#include <iostream>
#include <fstream>
#include <vector>
#include <cstring>
#include <openssl/evp.h>

using namespace std;

// PKCS#7 填充
void pkcs7_pad(vector<unsigned char>& data, size_t block_size) {
    size_t padding = block_size - (data.size() % block_size);
    data.insert(data.end(), padding, static_cast<unsigned char>(padding));
}

// PKCS#7 去填充
bool pkcs7_unpad(vector<unsigned char>& data) {
    if (data.empty()) return false;
    unsigned char padding = data.back();
    if (padding == 0 || padding > data.size()) return false;
    for (size_t i = data.size() - padding; i < data.size(); ++i) {
        if (data[i] != padding) return false;
    }
    data.resize(data.size() - padding);
    return true;
}

// AES-128-ECB 加密
bool aes_encrypt(const vector<unsigned char>& plaintext, vector<unsigned char>& ciphertext, const unsigned char key[16]) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;

    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), nullptr, key, nullptr)) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    EVP_CIPHER_CTX_set_padding(ctx, 0); // 我们自己填充

    int outlen1 = (int)plaintext.size() + 16;
    ciphertext.resize(outlen1);

    int len1 = 0;
    if (1 != EVP_EncryptUpdate(ctx, ciphertext.data(), &len1, plaintext.data(), (int)plaintext.size())) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    int len2 = 0;
    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext.data() + len1, &len2)) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    ciphertext.resize(len1 + len2);
    EVP_CIPHER_CTX_free(ctx);
    return true;
}

// AES-128-ECB 解密
bool aes_decrypt(const vector<unsigned char>& ciphertext, vector<unsigned char>& plaintext, const unsigned char key[16]) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;

    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_128_ecb(), nullptr, key, nullptr)) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    EVP_CIPHER_CTX_set_padding(ctx, 0); // 我们自己去填充

    int outlen1 = (int)ciphertext.size();
    plaintext.resize(outlen1);

    int len1 = 0;
    if (1 != EVP_DecryptUpdate(ctx, plaintext.data(), &len1, ciphertext.data(), (int)ciphertext.size())) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    int len2 = 0;
    if (1 != EVP_DecryptFinal_ex(ctx, plaintext.data() + len1, &len2)) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    plaintext.resize(len1 + len2);
    EVP_CIPHER_CTX_free(ctx);
    return true;
}

int main() {
    // AES密钥（16字节）
    unsigned char key[16] = {
        0x60, 0x3d, 0xeb, 0x10,
        0x15, 0xca, 0x71, 0xbe,
        0x2b, 0x73, 0xae, 0xf0,
        0x85, 0x7d, 0x77, 0x81
    };

    // 明文示例
    string plaintext_str = "Hello AES ECB!";

    // 转为字节向量
    vector<unsigned char> plaintext(plaintext_str.begin(), plaintext_str.end());

    // 填充
    pkcs7_pad(plaintext, 16);

    vector<unsigned char> ciphertext;
    if (!aes_encrypt(plaintext, ciphertext, key)) {
        cerr << "AES加密失败" << endl;
        return 1;
    }

    vector<unsigned char> decrypted;
    if (!aes_decrypt(ciphertext, decrypted, key)) {
        cerr << "AES解密失败" << endl;
        return 1;
    }

    // 去填充
    if (!pkcs7_unpad(decrypted)) {
        cerr << "去填充失败，可能密钥错误或数据损坏" << endl;
        return 1;
    }

    string decrypted_str(decrypted.begin(), decrypted.end());

    cout << "原始明文: " << plaintext_str << endl;
    cout << "加密后数据(hex): ";
    for (unsigned char c : ciphertext) {
        printf("%02x", c);
    }
    cout << endl;
    cout << "解密后明文: " << decrypted_str << endl;

    return 0;
}
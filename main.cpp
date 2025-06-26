#include <iostream>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <string>
#include <vector>
#include <openssl/aes.h>
#include <openssl/des.h>
#include <openssl/sha.h>
#include <cstring>

using namespace std;

string trimQuotes(const string& s) {
    if (s.size() >= 2 && s.front() == '"' && s.back() == '"')
        return s.substr(1, s.size() - 2);
    return s;
}

string sha256sum(const string& filepath) {
    ifstream file(filepath, ios::binary);
    if (!file) return "";

    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    char buffer[8192];
    while (file.read(buffer, sizeof(buffer)))
        SHA256_Update(&ctx, buffer, file.gcount());
    if (file.gcount() > 0)
        SHA256_Update(&ctx, buffer, file.gcount());

    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_Final(hash, &ctx);

    stringstream ss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i)
        ss << hex << setw(2) << setfill('0') << (int)hash[i];
    return ss.str();
}

void pkcs7Pad(vector<unsigned char>& data) {
    size_t padLen = AES_BLOCK_SIZE - (data.size() % AES_BLOCK_SIZE);
    data.insert(data.end(), padLen, static_cast<unsigned char>(padLen));
}

void pkcs7Unpad(vector<unsigned char>& data) {
    if (data.empty()) return;
    unsigned char padLen = data.back();
    if (padLen > 0 && padLen <= AES_BLOCK_SIZE)
        data.resize(data.size() - padLen);
}

void aes_encrypt_file(const string& inFile, const string& outFile, const unsigned char* key) {
    ifstream fin(inFile, ios::binary);
    ofstream fout(outFile, ios::binary);
    if (!fin || !fout) {
        cerr << "无法打开文件" << endl;
        return;
    }

    AES_KEY aesKey;
    AES_set_encrypt_key(key, 128, &aesKey);

    vector<unsigned char> buffer((istreambuf_iterator<char>(fin)), {});
    pkcs7Pad(buffer);

    for (size_t i = 0; i < buffer.size(); i += AES_BLOCK_SIZE) {
        unsigned char out[AES_BLOCK_SIZE];
        AES_encrypt(&buffer[i], out, &aesKey);
        fout.write(reinterpret_cast<char*>(out), AES_BLOCK_SIZE);
    }
}

void aes_decrypt_file(const string& inFile, const string& outFile, const unsigned char* key) {
    ifstream fin(inFile, ios::binary);
    ofstream fout(outFile, ios::binary);
    if (!fin || !fout) {
        cerr << "无法打开文件" << endl;
        return;
    }

    AES_KEY aesKey;
    AES_set_decrypt_key(key, 128, &aesKey);

    vector<unsigned char> buffer((istreambuf_iterator<char>(fin)), {});
    if (buffer.size() % AES_BLOCK_SIZE != 0) {
        cerr << "AES解密失败，可能密钥错误或文件格式错误" << endl;
        return;
    }

    vector<unsigned char> decrypted;
    for (size_t i = 0; i < buffer.size(); i += AES_BLOCK_SIZE) {
        unsigned char out[AES_BLOCK_SIZE];
        AES_decrypt(&buffer[i], out, &aesKey);
        decrypted.insert(decrypted.end(), out, out + AES_BLOCK_SIZE);
    }

    pkcs7Unpad(decrypted);
    fout.write(reinterpret_cast<char*>(decrypted.data()), decrypted.size());
}

void des_encrypt_file(const string&, const string&, const string&);
void des_decrypt_file(const string&, const string&, const string&);

int main() {
    int choice;
    cout << "请选择操作:\n"
         << "1. AES 加密\n"
         << "2. AES 解密\n"
         << "3. DES 加密\n"
         << "4. DES 解密\n"
         << "选择: ";
    cin >> choice;

    string inFile, outFile;
    cout << "输入文件路径: ";
    cin >> inFile;
    inFile = trimQuotes(inFile);
    cout << "输出文件路径: ";
    cin >> outFile;
    outFile = trimQuotes(outFile);

    if (choice == 1 || choice == 2) {
        cout << "请输入16字节16进制AES密钥（32个十六进制字符）: ";
        string hexKey;
        cin >> hexKey;
        if (hexKey.length() != 32) {
            cerr << "密钥长度错误！应为32个十六进制字符。" << endl;
            return 1;
        }

        unsigned char key[16];
        for (int i = 0; i < 16; ++i) {
            key[i] = static_cast<unsigned char>(stoul(hexKey.substr(i * 2, 2), nullptr, 16));
        }

        try {
            if (choice == 1) {
                aes_encrypt_file(inFile, outFile, key);
                string hash = sha256sum(inFile);
                string hashFile = outFile + ".hash";
                ofstream hout(hashFile);
                if (hout) {
                    hout << hash << endl;
                    cout << "\n🔐 加密完成，已生成原文件哈希：" << hash << endl;
                    cout << "📄 哈希已保存到文件: " << hashFile << endl;
                } else {
                    cerr << "❗ 无法写入哈希文件。" << endl;
                }
            } else {
                aes_decrypt_file(inFile, outFile, key);
                string hashFile = inFile + ".hash";
                ifstream hin(hashFile);
                if (!hin) {
                    cerr << "❗ 未找到哈希文件（" << hashFile << "），无法验证解密正确性。" << endl;
                } else {
                    string storedHash;
                    getline(hin, storedHash);
                    string newHash = sha256sum(outFile);
                    cout << "\n🔍 哈希校验结果:" << endl;
                    cout << "原始哈希:   " << storedHash << endl;
                    cout << "当前哈希:   " << newHash << endl;

                    if (storedHash == newHash) {
                        cout << "✅ 哈希校验通过：文件内容正确，还原成功！" << endl;
                    } else {
                        cout << "❌ 哈希校验失败：文件可能已损坏、被篡改，或密钥错误！" << endl;
                    }
                }
            }
        } catch (exception& e) {
            cerr << "AES 操作失败: " << e.what() << endl;
            return 1;
        }
    } else {
        cout << "请输入16位16进制DES密钥（16个十六进制字符）: ";
        string desKey;
        cin >> desKey;
        try {
            if (choice == 3)
                des_encrypt_file(inFile, outFile, desKey);
            else
                des_decrypt_file(inFile, outFile, desKey);
        } catch (exception& e) {
            cerr << "DES 操作失败: " << e.what() << endl;
            return 1;
        }
    }

    cout << "\n✅ 操作完成，输出文件：" << outFile << endl;
    return 0;
}
#ifndef VAULT_H
#define VAULT_H
#include <cstdlib>
#include <string>
#include <unordered_map>
#include <fstream>
#include <iostream>
#include <filesystem>
#include "data.h"
#include "aes256.h"


class vault{
private:

    std::string vaultPath;
    std::unordered_map<std::string, std::string> vaultMap;
    aes256 aes;
    
    void getVault();

    void saveVault();

public:

    vault(uint8_t* key);

    ~vault();

    std::string takePasswdFromUser();
    void addPasswordToVault(const std::string& name, const std::string& password);

    const std::unordered_map<std::string, std::string>& getMap() const;

    static data moveTextIntoMatrix(uint8_t* plainText,const int&size);

    static uint8_t* keyToBytes(const char* key);
};

#endif
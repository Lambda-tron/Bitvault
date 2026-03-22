#include "vault.h"

void vault::getVault(){
    std::ifstream file(vaultPath, std::ios::binary | std::ios::ate);
    std::streamsize size = file.tellg();
    file.seekg(0, std::ios::beg);

    uint8_t* buffer = new uint8_t[size];

    file.read(reinterpret_cast<char*>(buffer), size);

    data vaultMatrixData = moveTextIntoMatrix(buffer, size);

    delete[] buffer;

    //load the whole file and all characters
    this->aes.decrypt(vaultMatrixData);
    
    //loadVault
    std::string first;
    std::string second;
    bool passed = false;
    for(int row = 0, fileInex=0; row<vaultMatrixData.numRows; row++){
        for(int column = 0; column<4; column++,fileInex++){
            char ch = static_cast<char>(vaultMatrixData.message_bytes[row][column]);
            if(ch == ':'){
                passed=true;
            }else if (ch == '\n') {
                passed=false;
                this->vaultMap[first]=second;
                first="";
                second="";
            }else{
                if(passed){
                    second+=ch;
                }else{
                    first+=ch;
                }
            }
        }
    }
}

void vault::saveVault(){
    std::filesystem::path path = vaultPath;
    // create directory
    std::filesystem::create_directories(path.parent_path());
    // now create/open the vault
    std::ofstream vault(vaultPath);

    //store file into a variable
    std::string vaultData;
    for (auto& it: this->vaultMap) {
        vaultData += it.first + ":" + it.second + "\n";
    }

    //convert to bytes
    uint8_t* bytes = new uint8_t[vaultData.size()]{0};
    for(int i = 0; i < vaultData.size(); i++){
        bytes[i] = vaultData[i];
    }

    //put into a matrix
    data vaultMatrixData = moveTextIntoMatrix(bytes, vaultData.size());
    //encrypt
    this->aes.encrypt(vaultMatrixData);

    //start writing bytes to the file
    for(int row = 0; row<vaultMatrixData.numRows; row++){
        for(int column = 0; column<4; column++){
            vault << vaultMatrixData.message_bytes[row][column];
        }
    }
    
    vault.close();

    std::cout << "Password saved successfully\n";
}



vault::vault(uint8_t* key) : aes(key) {
    const char* home = std::getenv("HOME");
    if (home) {
        this->vaultPath = std::string(home) + "/.local/share/bitvault/default.vlt";
    } else {
        this->vaultPath = "./default.vlt";
    }
    getVault();
}

vault::~vault() = default;

void vault::addPasswordToVault(const std::string& name, const std::string& password){
    auto it = this->vaultMap.find(name);

    if (it != this->vaultMap.end()) {
        std::cout << "Entry '" << name << "' already exists.\n";
        std::cout << "Overwrite? [Y/n]: ";

        std::string input;
        std::getline(std::cin, input);

        // Default = YES (overwrite)
        if (input == "n" || input == "N") {
            std::cout << "Operation cancelled.\n";
            return;
        }
    }

    this->vaultMap[name]= password;
    saveVault();
}

const std::unordered_map<std::string, std::string>& vault::getMap() const {
    return vaultMap;
}


data vault::moveTextIntoMatrix(uint8_t* plainText, const int& size) {
    int paddedSize = ((size + 15) / 16) * 16;
    int numBlocks = paddedSize / 16;
    int numRows = numBlocks * 4;

    data matrixInfo;
    matrixInfo.numRows = numRows;
    matrixInfo.message_bytes = new uint8_t*[numRows];

    for (int row = 0, byteIndex = 0; row < numRows; row++) {
        matrixInfo.message_bytes[row] = new uint8_t[4]{0};

        for (int column = 0; column < 4; column++) {
            if (byteIndex < size) {
                matrixInfo.message_bytes[row][column] = plainText[byteIndex++];
            } else {
                matrixInfo.message_bytes[row][column] = 0; // padding
            }
        }
    }

    return matrixInfo;
}

uint8_t* vault::keyToBytes(const char* key){
    uint8_t* keyBits = new uint8_t[32]{0};
    for(int i = 0; key[i] != '\0'; i++){
        keyBits[i] = (uint8_t)key[i];
    }
    return keyBits;
}

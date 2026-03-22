#include <iostream>
#include <string>
#include <iomanip>
#include "aes256.h"
#include "vault.h"
#include "data.h"
#include <unordered_map>
#include <cstdlib>



void printManual(bool showBanner = false){
    if (showBanner) {
        std::cout << "========================================\n";
        std::cout << "              BitVault\n";
        std::cout << "========================================\n";
        std::cout << "   Secure. Simple. Yours.\n\n";
        std::cout << "   Made with love and pointers <3\n";
        std::cout << "========================================\n\n";
    }

    std::cout << "Usage:\n";
    std::cout << "  ./bitvault <command> [options]\n\n";

    std::cout << "Commands:\n";
    std::cout << "  add <name> <password>\n";
    std::cout << "  get <name>\n";
    std::cout << "  get -a | --all\n";
    std::cout << "  test\n";
    std::cout << "  help\n\n";

    std::cout << "Examples:\n";
    std::cout << "  ./bitvault add github myPassword123\n";
    std::cout << "  ./bitvault get github\n";
    std::cout << "  ./bitvault get -a\n";
    std::cout << "  ./bitvault test\n\n";
}

void runEncryptionAlgoTest(){
	//test Key expansion, test key & Cipher test brought from nist.gov, expected result can be seen nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf?page=30
	std::cout << "Running key expansion test: " << "\n";
	std::cout << "60 3d eb 10 15 ca 71 be 2b 73 ae f0 85 7d 77 81 1f 35 2c 07 3b 61 08 d7 2d 98 10 a3 09 14 df f4" << "\n";

	uint8_t* testKey = new uint8_t[32]{
		0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe,
		0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
		0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7,
		0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4
	};
	aes256 aes = aes256(testKey);
	aes.testKeyExpansion();
	
	delete[] testKey;
	
	std::cout << "Running Cipher test: " << "\n";
	std:: cout << "Plain Text: 00 11 22 33 44 55 66 77 88 99 aa bb cc dd ee ff" << "\n";
	std:: cout << "Key: 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f 10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f" << "\n";
	
	uint8_t* plainText = new uint8_t[16]{
		0x00, 0x11, 0x22, 0x33,
		0x44, 0x55, 0x66, 0x77,
		0x88, 0x99, 0xaa, 0xbb,
		0xcc, 0xdd, 0xee, 0xff
	};

	testKey = new uint8_t[32]{
		0x00, 0x01, 0x02, 0x03,
		0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b,
		0x0c, 0x0d, 0x0e, 0x0f,
		0x10, 0x11, 0x12, 0x13, 
		0x14, 0x15, 0x16, 0x17, 
		0x18, 0x19, 0x1a, 0x1b, 
		0x1c, 0x1d, 0x1e, 0x1f
	};

	//aes.testKeyExpansion(testKey);
	data dataInfo = vault::moveTextIntoMatrix(plainText,16);
	std::cout << "Plain Text: " << "\n";
	aes256::print_blocks(dataInfo);
	aes.encrypt(dataInfo);
	std::cout << "Encrypted: " << "\n";
	aes256::print_blocks(dataInfo);
	aes.decrypt(dataInfo);
	std::cout << "Decrypted: " << "\n";
	aes256::print_blocks(dataInfo);

	delete[] testKey;
}

int main(int argc, char* argv[]) {

    if (argc < 2) {
		printManual(true);
        return 0;
    }
 
    std::string command = argv[1];

	if (command == "help") {
		printManual(true);
		return 0;
	}

    if (command == "test") {
        runEncryptionAlgoTest();
        return 0;
    }

	std::string s_key;
    std::cout << "Please Enter The Vaults Key [Maximum of 32 characters]: ";
	getline(std::cin,s_key);
	uint8_t* byteKey = vault::keyToBytes((const char*)(s_key.c_str())); 
	vault vlt = vault(byteKey);
    if (command == "get") {
        if (argc < 3) {
            std::cout << "Error: missing name or option for 'get'.\n\n";
            printManual();
            return 1;
        }
        std::unordered_map<std::string, std::string> vaultMap = vlt.getMap();

        std::string target = argv[2];



		if (target == "-a" || target == "--all") {
			std::cout << "Stored passwords:\n";
			std::cout << "-----------------------------------------------\n";

			// Find longest name
			size_t maxWidth = 4; // length of "Name"
			for (const auto& entry : vaultMap) {
				if (entry.first.length() > maxWidth) {
					maxWidth = entry.first.length();
				}
			}

			maxWidth += 4; // padding

			// Header
			std::cout << std::left << std::setw(maxWidth) << "Name" << "Password\n";
			std::cout << "-----------------------------------------------\n";

			// Rows
			for (const auto& entry : vaultMap) {
				std::cout << std::left << std::setw(maxWidth)<< entry.first << entry.second << "\n";
			}

			return 0;
		}

        auto it = vaultMap.find(target);
        if (it != vaultMap.end()) {
			std::cout << "Entry: " << target << "\n";
			std::cout << "Password: " << it->second << "\n";
        } else {
            std::cout << "Error: no password found for '" << target << "'.\n";
            return 1;
        }

        return 0;
    }

    if (command == "add") {
        if (argc < 4) {
            std::cout << "Error: missing name or password for 'add'.\n\n";
            printManual();
            return 1;
        }
        vlt.addPasswordToVault(argv[2], argv[3]);
        return 0;
    }

    std::cout << "Error: unknown command '" << command << "'.\n\n";
    printManual();
    return 1;
}
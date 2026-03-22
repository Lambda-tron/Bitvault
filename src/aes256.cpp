#include "aes256.h"


void aes256::print_blocks(const data &dataInfo) {
    for (int row = 0; row < dataInfo.numRows; row++) {
        std::cout << std::hex
                << std::setw(2) << std::setfill('0') << int(dataInfo.message_bytes[row][0]) << " "
                << std::setw(2) << std::setfill('0') << int(dataInfo.message_bytes[row][1]) << " "
                << std::setw(2) << std::setfill('0') << int(dataInfo.message_bytes[row][2]) << " "
                << std::setw(2) << std::setfill('0') << int(dataInfo.message_bytes[row][3]) << "\n";
    }
}

void aes256::encrypt(data &dataInfo){
    //transpose the plainText
    //Message is devided into equally 16 bytes arrays (4x4 bytes matrix)
    //transpose
    transposeMatrix(dataInfo.message_bytes,dataInfo.numRows);

    //loop through each block
    //start preforming encryption
    for(int blk_frst_row = 0; blk_frst_row < dataInfo.numRows ; blk_frst_row+=4){
        
        //add the first roundkey
        for(int i = 0; i < 4 ; i++){
            XOR(dataInfo.message_bytes[blk_frst_row + i], keys[i]);
        }
        
        //14 rounds
        for(int rounds = 1; rounds < 15 ; rounds++){


            //subbyte
            for(int index = blk_frst_row; index < blk_frst_row+4 ; index++){
                substitue(dataInfo.message_bytes[index]);
            
            }

            //shiftrows
            for(int index = blk_frst_row,times=0; index < blk_frst_row+4 ; index++,times++){
                rotWord(dataInfo.message_bytes[index],times);
            }

            //mixColoumn
            if(rounds<14){
                for(int coloumn=0; coloumn < 4 ; coloumn++){
                    mixColumns(dataInfo.message_bytes[blk_frst_row][coloumn], dataInfo.message_bytes[blk_frst_row+1][coloumn], dataInfo.message_bytes[blk_frst_row+2][coloumn], dataInfo.message_bytes[blk_frst_row+3][coloumn]);	
                }					
            }
            
            //add roundkey
            for(int i = 0; i < 4; i++){
                XOR(dataInfo.message_bytes[blk_frst_row + i], keys[rounds * 4 + i]);
            }

        }
    }
}

void aes256::decrypt(data &dataInfo){
    //start decryption
    for(int blk_frst_row = 0; blk_frst_row < dataInfo.numRows ; blk_frst_row+=4){
        
        //add the first round key schedule
        for(int i = 0; i < 4 ; i++){
            XOR(dataInfo.message_bytes[blk_frst_row + i], keys[56 + i]);
        }
        
        //14 rounds
        for(int rounds = 1; rounds < 15 ; rounds++){

            //shiftrows
            for(int index = blk_frst_row,times=0; index < blk_frst_row+4 ; index++,times++){
                inv_rotWord(dataInfo.message_bytes[index],times);
            }

            //subbyte
            for(int index = blk_frst_row; index < blk_frst_row+4 ; index++){
                inv_substitue(dataInfo.message_bytes[index]);
            
            }

            //add roundkey
            for(int i = 0; i < 4; i++){
                XOR(dataInfo.message_bytes[blk_frst_row + i], keys[56 - (rounds * 4) + i]);
            }
            
            //mixColoumn
            if(rounds<14){
                for(int coloumn=0; coloumn < 4 ; coloumn++){
                    inv_mixColumns(dataInfo.message_bytes[blk_frst_row][coloumn], dataInfo.message_bytes[blk_frst_row+1][coloumn], dataInfo.message_bytes[blk_frst_row+2][coloumn], dataInfo.message_bytes[blk_frst_row+3][coloumn]);	
                }					
            }

        }
    }
    transposeMatrix(dataInfo.message_bytes, dataInfo.numRows);
}

aes256::~aes256()=default;

aes256::aes256(uint8_t* key){
    //preform key expansion.
    keyExpansion(key);
}

void aes256::testKeyExpansion(){
    for (int i = 0; i < 60; i++) {
        std::cout << "W_" << i << ": "; 

        for (int j = 0; j < 4; j++) {
            std::cout << std::hex << (int)keys[i][j] << " ";
        }

        std::cout << std::dec << "\n"; 
    }
}

uint8_t aes256::gf_mult(uint8_t a, uint8_t b) {
    uint8_t result = 0;
    
    for (int i = 0; i < 8; i++) {
        // If current bit of b is set, XOR a into result
        if (b & 1) {
            result ^= a;
        }
        
        // Check if a will overflow when shifted
        uint8_t hi_bit = a & 0x80;
        a <<= 1;  // Multiply by {02}
        
        if (hi_bit) {
            a ^= 0x1B;  // Reduce modulo polynomial
        }
        
        b >>= 1;  // Move to next bit of coefficient
    }
    
    return result;
}

void aes256::mixColumns(uint8_t &col1, uint8_t &col2, uint8_t &col3, uint8_t &col4) {
    uint8_t n_col1,n_col2,n_col3,n_col4;
    n_col1 = gf_mult(col1,2) ^ gf_mult(col2,3) ^ col3 ^ col4;
    n_col2 = col1 ^ gf_mult(col2,2) ^ gf_mult(col3,3) ^ col4;
    n_col3 = col1 ^ col2 ^ gf_mult(col3,2) ^ gf_mult(col4,3);
    n_col4 = gf_mult(col1,3) ^ col2 ^ col3 ^ gf_mult(col4,2);
    col1 = n_col1; col2 = n_col2; col3 = n_col3; col4 = n_col4;
}

void aes256::XOR(uint8_t* state, uint8_t word[4], bool print) {

    if (print) {
        std::cout << "Before XOR:\nState: ";
        for (int i = 0; i < 4; i++) {
            std::cout << std::hex << std::setw(2) << std::setfill('0')
                    << int(state[i]) << " ";
        }

        std::cout << "\nWord : ";
        for (int i = 0; i < 4; i++) {
            std::cout << std::hex << std::setw(2) << std::setfill('0')
                    << int(word[i]) << " ";
        }
        std::cout << "\n";
    }

    // XOR
    for (int i = 0; i < 4; i++) {
        state[i] ^= word[i];
    }

    if (print) {
        std::cout << "After XOR:\nState: ";
        for (int i = 0; i < 4; i++) {
            std::cout << std::hex << std::setw(2) << std::setfill('0')<< int(state[i]) << " ";
        }
        std::cout << "\n\n";
    }
}

void aes256::inv_mixColumns(uint8_t &col1, uint8_t &col2, uint8_t &col3, uint8_t &col4) {
    uint8_t n_col1,n_col2,n_col3,n_col4;
    n_col1 = gf_mult(col1,0x0e) ^ gf_mult(col2,0x0b) ^ gf_mult(col3,0x0d) ^ gf_mult(col4,0x09);
    n_col2 = gf_mult(col1,0x09) ^ gf_mult(col2,0x0e) ^ gf_mult(col3,0x0b) ^ gf_mult(col4,0x0d);
    n_col3 = gf_mult(col1,0x0d) ^ gf_mult(col2,0x09) ^ gf_mult(col3,0x0e) ^ gf_mult(col4,0x0b);
    n_col4 = gf_mult(col1,0x0b) ^ gf_mult(col2,0x0d) ^ gf_mult(col3,0x09) ^ gf_mult(col4,0x0e);
    col1 = n_col1; col2 = n_col2; col3 = n_col3; col4 = n_col4;
}

void aes256::inv_rotWord(uint8_t* word, int times){
    int i = 0;
    while(i < times){
        uint8_t last = word[3];
        word[3] = word[2];
        word[2] = word[1];
        word[1] = word[0];
        word[0] = last;
        i++;
    }

}

void aes256::keyExpansion(uint8_t *k){
    rconIndex = 0;
    //fill the first 8 words / 32 bits  with the original key;
    for(int w=0,i_byte=0; i_byte<32; i_byte++){
        if(keys[w] == nullptr){keys[w] = new uint8_t[4]{0};}
            
        this->keys[w][i_byte%4] = k[i_byte];
        if(i_byte % 4 == 3){ w++; }
    }

    //key expantion
    for(int i = 8; i<60 ; i++){
        if(keys[i] == nullptr){keys[i] = new uint8_t[4]{0};}
        memcpy(this->keys[i], this->keys[i-1], 4);
        //take every 8th word/4 bytes and preform key scheduel on it
        if(i%8==0){
            //coloumn left rotation
            rotWord(this->keys[i]);
            //byte substitution
            substitue(this->keys[i]);
            this->keys[i][0] ^= rcon[this->rconIndex];
            this->rconIndex++;
        }else if (i%4==0){
            //byte substitution
            substitue(this->keys[i]);
        }
        //XOR on the 8th word from behind
        XOR(this->keys[i],this->keys[i-8]);
    }

    //transpose the matrix now, 16 bytes at a time
    transposeMatrix(keys,60);

}

void aes256::rotWord(uint8_t* word, int times){
    int i = 0;
    while(i < times){
        uint8_t first = word[0];
        word[0] = word[1];
        word[1] = word[2];
        word[2] = word[3];
        word[3] = first;
        i++;
    }

}

void aes256::transposeMatrix(uint8_t** matrix, const int& numRows) {
    // Calculate number of 4x4 blocks to transpose
    int numBlocks = numRows / 4;
    
    // Transpose each 4x4 block
    for (int block = 0; block < numBlocks; block++) {
        int startWord = block * 4;
        
        // Create temporary storage for the transposed block
        uint8_t temp[4][4];
        
        // Copy current 4 words into temp matrix (column-major)
        for (int word = 0; word < 4; word++) {
            for (int byte = 0; byte < 4; byte++) {
                temp[byte][word] = matrix[startWord + word][byte];
            }
        }
        
        // Write back in row-major order (transposed)
        for (int word = 0; word < 4; word++) {
            for (int byte = 0; byte < 4; byte++) {
                matrix[startWord + word][byte] = temp[word][byte];
            }
        }
    }
}

void aes256::substitue(uint8_t *word ){
    for(int i = 0; i<4; i++){
        word[i] = sbox[word[i]];
    }
}

void aes256::inv_substitue(uint8_t *word ){
    for(int i = 0; i<4; i++){
        word[i] = inv_sbox[word[i]];
    }
}
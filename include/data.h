#ifndef DATA_H
#define DATA_H 

#include <vector>
struct data{
    uint8_t** message_bytes = nullptr;
    int numRows = 0;
    ~data() {
        if (message_bytes) {
            for (int i = 0; i < numRows; i++) {
                delete[] message_bytes[i];
            }
            delete[] message_bytes;
        }

    }
};

struct creds{
    uint8_t* name;
    uint8_t* pass;
};


#endif
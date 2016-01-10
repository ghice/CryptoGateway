//Primary author: Jonathan Bedard
//Confirmed working: 1/10/2016

#ifndef RC4_HASH_H
#define RC4_HASH_H

#include <string>
#include <iostream>
#include <stdlib.h>

#include "cryptoHash.h"
#include "streamCipher.h"

namespace crypto {

	extern bool global_logging;

	//RC-4 hash
    class rc4Hash:public hash
    {
    private:
        rc4Hash(const unsigned char* data, uint32_t length, uint16_t size);
    public:
        inline static std::string staticAlgorithmName() {return "RC-4";}
        inline static uint16_t staticAlgorithm() {return algo::hashRC4;}
        
        rc4Hash():hash(rc4Hash::staticAlgorithm()){}
        rc4Hash(const unsigned char* data, uint16_t size);
        rc4Hash(const rc4Hash& cpy):hash(cpy){}
        void preformHash(const unsigned char* data, uint32_t dLen);
        inline std::string algorithmName() const {return rc4Hash::staticAlgorithmName();}
        
        static rc4Hash hash64Bit(const unsigned char* data, uint32_t length){return rc4Hash(data,length,size::hash64);}
        static rc4Hash hash128Bit(const unsigned char* data, uint32_t length){return rc4Hash(data,length,size::hash128);}
        static rc4Hash hash256Bit(const unsigned char* data, uint32_t length){return rc4Hash(data,length,size::hash256);}
        static rc4Hash hash512Bit(const unsigned char* data, uint32_t length){return rc4Hash(data,length,size::hash512);}
    };
}

#endif
//Primary author: Jonathan Bedard
//Confirmed working: 1/10/2016

#ifndef CRYPTO_HASH_H
#define CRYPTO_HASH_H

#include <string>
#include <iostream>
#include <stdlib.h>

#include "hexConversion.h"
#include "cryptoConstants.h"

namespace crypto {

    class hash;
    std::ostream& operator<<(std::ostream& os, const hash& num);
    std::istream& operator>>(std::istream& is, hash& num);
    
    //Basic hash
    class hash
    {
        uint16_t _algorithm;
    protected:
        uint16_t _size;
        unsigned char* _data;
        
        hash(uint16_t algorithm=algo::hashNULL,uint16_t size=size::defaultHash);
    public:
        inline static std::string staticAlgorithmName() {return "NULL";}
        inline static uint16_t staticAlgorithm() {return algo::hashNULL;}
        
        hash(const hash& cpy);
        hash& operator=(const hash& cpy);
        virtual ~hash();
        int compare(const hash* _comp) const;
        
        virtual void preformHash(unsigned char* data, uint32_t dLen){}
        
        //Return functions
        inline virtual std::string algorithmName() const {return hash::staticAlgorithmName();}
        inline uint16_t algorithm() const {return _algorithm;}
        inline uint16_t size() const {return _size;}
        inline uint32_t numBits() const {return _size*8;}
        inline unsigned char* data() {return _data;}
        inline const unsigned char* data() const {return _data;}
        
        //Operator access
        unsigned char operator[](uint16_t pos) const;
        unsigned char& operator[](uint16_t pos);
        
        //String Conversion
        std::string toString() const;
        void fromString(const std::string& str);
        friend std::ostream& operator<<(std::ostream& os, const hash& num);
        friend std::istream& operator>>(std::istream& is, hash& num);
        
        //Comparison functions
        bool operator==(const hash& comp) const{return compare(&comp)==0;}
        bool operator!=(const hash& comp) const{return compare(&comp)!=0;}
        
        bool operator>(const hash& comp) const{return compare(&comp)==1;}
        bool operator>=(const hash& comp) const{return compare(&comp)>=0;}
        
        bool operator<(const hash& comp) const{return compare(&comp)==-1;}
        bool operator<=(const hash& comp) const{return compare(&comp)<=0;}
    };

    //Basic hash funciton
    template <class hashClass>
    hashClass hashData(uint16_t hashType,const unsigned char* data, uint32_t length)
    {
        if(hashType==size::hash64)
            return hashClass::hash64Bit(data,length);
        else if(hashType==size::hash128)
            return hashClass::hash128Bit(data,length);
        else if(hashType==size::hash256)
            return hashClass::hash256Bit(data,length);
        else if(hashType==size::hash512)
            return hashClass::hash512Bit(data,length);
        return hashClass::hash256Bit(data,length);
    }
    
    
    //XOR hash
    class xorHash:public hash
    {
    private:
        xorHash(const unsigned char* data, uint32_t length, uint16_t size);
    public:
        inline static std::string staticAlgorithmName() {return "XOR";}
        inline static uint16_t staticAlgorithm() {return algo::hashXOR;}
        
        xorHash():hash(xorHash::staticAlgorithm()){}
        xorHash(const unsigned char* data, uint16_t size);
        xorHash(const xorHash& cpy):hash(cpy){}
        void preformHash(const unsigned char* data, uint32_t dLen);
        inline std::string algorithmName() const {return xorHash::staticAlgorithmName();}
        
        static xorHash hash64Bit(const unsigned char* data, uint32_t length){return xorHash(data,length,size::hash64);}
        static xorHash hash128Bit(const unsigned char* data, uint32_t length){return xorHash(data,length,size::hash128);}
        static xorHash hash256Bit(const unsigned char* data, uint32_t length){return xorHash(data,length,size::hash256);}
        static xorHash hash512Bit(const unsigned char* data, uint32_t length){return xorHash(data,length,size::hash512);}
    };
}

#endif
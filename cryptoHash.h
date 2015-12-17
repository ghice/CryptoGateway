//Primary author: Jonathan Bedard
//Confirmed working: 12/17/2015

#ifndef CRYPTO_HASH_H
#define CRYPTO_HASH_H

#include <string>
#include <iostream>
#include <stdlib.h>

#include "cryptoConstants.h"

namespace crypto {

    //Basic hash
    class hash
    {
        uint16_t _algorithm;
        uint16_t _size;
        char* _data;
    
        int compare(const hash* _comp) const;
    protected:
        hash(uint16_t algorithm=algo::hashNULL,uint16_t size=size::defaultHash);
    public:
        hash(const hash& cpy);
        hash& operator=(const hash& cpy);
        virtual ~hash();
        
        virtual void preformHash(char* data, uint32_t dLen){}
        
        //Return functions
        uint16_t algorithm() const {return _algorithm;}
        uint16_t size() const {return _size;}
        uint32_t numBits() const {return _size*8;}
        char* data() {return _data;}
        const char* data() const {return _data;}
        
        //Comparison functions
        bool operator==(const hash& comp) const{return compare(&comp)==0;}
        bool operator!=(const hash& comp) const{return compare(&comp)!=0;}
        
        bool operator>(const hash& comp) const{return compare(&comp)==1;}
        bool operator>=(const hash& comp) const{return compare(&comp)>=0;}
        
        bool operator<(const hash& comp) const{return compare(&comp)==-1;}
        bool operator<=(const hash& comp) const{return compare(&comp)<=0;}
    };

}

#endif
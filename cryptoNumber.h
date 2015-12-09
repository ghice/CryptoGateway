//Primary author: Jonathan Bedard
//Confirmed working: 12/8/2015

#ifndef CRYPTO_NUMBER_H
#define CRYPTO_NUMBER_H

#include "cryptoCHeaders.h"
#include <string>

namespace crypto
{
    //Basic number
    class number
    {
    protected:
        struct numberType* _numDef;
        uint16_t _size;
        uint32_t* _data;
        
        int compare(const number& num) const;
    public:
        number(numberType* numDef=buildNullNumberType());
        number(uint16_t size, numberType* numDef=buildNullNumberType());
        number(uint32_t* d, uint16_t size, numberType* numDef=buildNullNumberType());
        number(const number& num);
        virtual ~number();
        
        //Comparison functions
        const bool operator==(const number& comp) const;
        const bool operator!=(const number& comp) const;
        const bool operator<=(const number& comp) const;
        const bool operator>=(const number& comp) const;
        const bool operator<(const number& comp) const;
        const bool operator>(const number& comp) const;
        
        //Raw Data Get
        uint16_t size() {return _size;}
        uint16_t size() const{return _size;}
        uint32_t* data() {return _data;}
        uint32_t* data() const{return _data;}
        
        //Number Type Access
        const struct numberType* numberDefinition() const {return _numDef;}
        int typeID() const {return _numDef->typeID;}
        std::string name() const {return std::string(_numDef->name);}
    };
}

#endif
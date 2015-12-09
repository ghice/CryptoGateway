//Primary author: Jonathan Bedard
//Confirmed working: 12/8/2015

#ifndef CRYPTO_NUMBER_H
#define CRYPTO_NUMBER_H

#include "cryptoConstants.h"
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
        number(struct numberType* numDef=buildNullNumberType());
        number(uint16_t size, struct numberType* numDef=buildNullNumberType());
        number(uint32_t* d, uint16_t size, struct numberType* numDef=buildNullNumberType());
        number(const number& num);
		number& operator=(const number& num);
        virtual ~number();
        
        //Size manipulation
        void reduce();
        void expand(uint16_t size);
        
        //To and from string
        std::string toString() const;
        void fromString(const std::string& str);
        friend std::ostream& operator<<(std::ostream& os, const number& num);
        friend std::istream& operator>>(std::istream& is, number& num);
        
		//Operator access
		uint32_t operator[](uint16_t pos) const;
		uint32_t& operator[](uint16_t pos);

        //Comparison functions
        const bool operator==(const number& comp) const;
        const bool operator!=(const number& comp) const;
        const bool operator<=(const number& comp) const;
        const bool operator>=(const number& comp) const;
        const bool operator<(const number& comp) const;
        const bool operator>(const number& comp) const;
        
        //Checks if the number definition defines functions
        inline bool hasCompare() const {return _numDef->compare;}
        inline bool hasAddition() const {return _numDef->addition;}
        inline bool hasSubtraction() const {return _numDef->subtraction;}
        inline bool hasRightShift() const {return _numDef->rightShift;}
        inline bool hasLeftShift() const {return _numDef->leftShift;}
        inline bool hasMultiplication() const {return _numDef->multiplication;}
        inline bool hasDivision() const {return _numDef->division;}
        inline bool hasModulo() const {return _numDef->modulo;}
        inline bool hasExponentiation() const {return _numDef->exponentiation;}
        inline bool hasModuloExponentiation() const {return _numDef->moduloExponentiation;}
        inline bool hasGCD() const {return _numDef->gcd;}
        inline bool hasModInverse() const {return _numDef->modInverse;}
        
        //Raw Data Get
        uint16_t size() {return _size;}
        uint16_t size() const{return _size;}
        uint32_t* data() {return _data;}
        uint32_t* data() const{return _data;}
        
        //Number Type Access
        inline const struct numberType* numberDefinition() const {return _numDef;}
        inline int typeID() const {return _numDef->typeID;}
        inline std::string name() const {return std::string(_numDef->name);}
    };
    
    //Integer
    class integer:public number
    {
    public:
        integer();
        integer(uint16_t size);
        integer(uint32_t* d, uint16_t size);
        integer(const integer& num);
    };
}

#endif
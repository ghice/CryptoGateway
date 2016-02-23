/**
 * @file	cryptoFrameworks.h
 * @author	Jonathan Bedard
 * @date   	2/22/2016
 * @brief	Deprecated public-key framework declaration
 * @bug	Deprecated
 *
 * Deprecated header file which
 * defines an old base class for
 * public key cryptography.  This
 * has been replaced by cryptoNumber.h
 **/

 ///@cond INTERNAL
#ifndef CRYPTO_FRAMEWORKS_H
#define CRYPTO_FRAMEWORKS_H

#include <iostream>
#include <stdint.h>
#include <cstdlib>
#include <string>
#include <exception>
#include "smartPointer.h"
#include "cryptoError.h"

namespace crypto
{
    //Public Field Type ID
    const unsigned int PUBLIC_FIELD_NO_TYPE=0;
    
    //Framework used for all public key "numbers"
    class publicField
    {
    private:
        unsigned int _typeID;
        uint16_t _fieldSize;
        os::smart_ptr<uint32_t> _data;
        uint32_t* raw_data;
    protected:
        
        uint32_t* modData(){return raw_data;}
    public:
        publicField(uint16_t fieldSize, unsigned int typeID=PUBLIC_FIELD_NO_TYPE, os::smart_ptr<uint32_t> data=NULL);
        publicField(const publicField& fd);
        virtual ~publicField();
        
        //Const access
        const uint16_t fieldSize() const {return _fieldSize;}
        const uint32_t* data() const {return raw_data;}
        const unsigned int typeID() const {return _typeID;}
        virtual const std::string& descriptor() const{return "Un-typed publicField";}
        
        //Accessors
        bool getBit(unsigned int bitLoc) const;
        uint32_t getArrayNumber(unsigned int index) const;
        const int compare(const publicField& comp) const;
        const uint32_t& operator[](unsigned int index) const throw (errorPointer);
        uint32_t& operator[](unsigned int index) throw (errorPointer);
        
        //Output
        std::string getHex() const;
        std::string getBinary() const;
        std::string get10() const;
        void printHex() const;
        void printBinary() const;
        void print10() const;
        friend std::ostream& operator<<(std::ostream& os, const publicField& obj);
        friend std::istream& operator>>(std::istream& os, const publicField& obj);
        
        //Comparison operators
        const publicField& operator=(const publicField& equ);
        virtual const bool operator<(const publicField& comp) const;
        virtual const bool operator>(const publicField& comp) const;
        virtual const bool operator<=(const publicField& comp) const;
        virtual const bool operator>=(const publicField& comp) const;
        virtual const bool operator==(const publicField& comp) const;
        virtual const bool operator!=(const publicField& comp) const;
    };
    
}

#endif

///@endcond
//Primary author: Jonathan Bedard
//Confirmed working: 11/1/2015

#ifndef CRYPTO_FRAMEWORKS_CPP
#define CRYPTO_FRAMEWORKS_CPP

#include "cryptoLogging.h"
#include "cryptoFrameworks.h"
#include "cryptoException.h"

using namespace crypto;

/********************************************************************
    Public Field
 ********************************************************************/

//Constructor---------------------------------------------------------

    //Construct with target size
    publicField::publicField(uint16_t fieldSize, unsigned int typeID, os::smart_ptr<uint32_t> data)
    {
        //Mark field size and type ID
        _fieldSize = fieldSize;
        _typeID = typeID;
        
        //Decide whether to hold the reference or use your own
        if(data==NULL || data.getType()<os::shared_type)
        {
            _data = os::smart_ptr<uint32_t>(new uint32_t[_fieldSize],os::shared_type);
            if(data)
            {
                for(unsigned int i = 0;i<_fieldSize;i++)
                    _data[i]=data[i];
            }
            else
            {
                for(unsigned int i = 0;i<_fieldSize;i++)
                    _data[i]=0;
            }
        }
        //Hold the reference
        else
            _data = data;
        raw_data = _data.get();
    }
    //Copy constructor
    publicField::publicField(const publicField& fd)
    {
        //Mark field size and type ID
        _fieldSize = fd._fieldSize;
        _typeID = fd._typeID;
        
        //Copy over
        _data = os::smart_ptr<uint32_t>(new uint32_t[_fieldSize],os::shared_type);
        for(unsigned int i = 0;i<_fieldSize;i++)
            _data[i]=fd._data.constGet()[i];
        raw_data = _data.get();
    }
    //Equality operator
    const publicField& publicField::operator=(const publicField& equ)
    {
        //Mark field size and type ID
        _fieldSize = equ._fieldSize;
        _typeID = equ._typeID;
        
        //Copy over
        _data = os::smart_ptr<uint32_t>(new uint32_t[_fieldSize],os::shared_type);
        for(unsigned int i = 0;i<_fieldSize;i++)
            _data[i]=equ._data.constGet()[i];
        raw_data = _data.get();
        return equ;
    }
    //Delete, virtual, smart pointer should expire
    publicField::~publicField(){}

//Const Access--------------------------------------------------------

    //Get bit
    bool publicField::getBit(unsigned int bitLoc) const
    {
        return raw_data[bitLoc>>5]&(1<<(bitLoc%32));
    }
    //Get array number
    uint32_t publicField::getArrayNumber(unsigned int index) const
    {
        if(index<_fieldSize)
            return raw_data[index];
        return 0;
    }
    //Compares two large_numbers (< is -1, = is 0 and > is 1)
    const int publicField::compare(const publicField& comp) const
    {
        int cnt = _fieldSize;
        if(comp._fieldSize>cnt)
            cnt = comp._fieldSize;
        cnt--;
        while(cnt>=0)
        {
            if(getArrayNumber(cnt)>comp.getArrayNumber(cnt))
                return 1;
            else if(getArrayNumber(cnt)<comp.getArrayNumber(cnt))
                return -1;
            cnt--;
        }
        return 0;
    }
    //Const []
    const uint32_t& publicField::operator[](unsigned int index) const throw (os::smart_ptr<std::exception>)
    {
        if(index>=_fieldSize)
            throw os::smart_ptr<std::exception>(new cryptoException("Element "+std::to_string(index)+" out of bounds of publicField []"),os::shared_type);
        return raw_data[index];
    }
    //Modifiable []
    uint32_t& publicField::operator[](unsigned int index) throw (os::smart_ptr<std::exception>)
    {
        if(index>=_fieldSize)
            throw os::smart_ptr<std::exception>(new cryptoException("Element "+std::to_string(index)+" out of bounds of publicField []"),os::shared_type);
        return raw_data[index];
    }

//Output---------------------------------------------------------------

    //Returns a hex string of the number
    std::string publicField::getHex() const
    {
        return "";
    }
    //Returns a binary string of the number
    std::string publicField::getBinary() const
    {
        return "";
    }
    //Return a base 10 string of the number
    std::string publicField::get10() const
    {
        return "";
    }
    //Crypto out Hex
    void publicField::printHex() const{cryptoout<<getHex()<<std::endl;}
    //Crypto out binary
    void publicField::printBinary() const{cryptoout<<getBinary()<<std::endl;}
    //Crypto out base 10
    void publicField::print10() const{cryptoout<<get10()<<std::endl;}
    //Outputs the public field in hex
    std::ostream& operator<<(std::ostream& os, const publicField& obj)
    {
        os<<obj.getHex();
        return os;
    }
    //Reads int from stream hex
    std::istream& operator>>(std::istream& os, const publicField& obj)
    {
        return os;
    }
//Comparison operators--------------------------------------------------

    const bool publicField::operator<(const publicField& comp) const{return compare(comp)==-1;}
    const bool publicField::operator>(const publicField& comp) const{return compare(comp)==1;}
    const bool publicField::operator<=(const publicField& comp) const{return compare(comp)!=1;}
    const bool publicField::operator>=(const publicField& comp) const{return compare(comp)!=-1;}
    const bool publicField::operator==(const publicField& comp) const{return compare(comp)==1;}
    const bool publicField::operator!=(const publicField& comp) const{return compare(comp)!=0;}

#endif

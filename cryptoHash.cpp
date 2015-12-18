//Primary author: Jonathan Bedard
//Confirmed working: 12/18/2015

#ifndef CRYPTO_HASH_CPP
#define CRYPTO_HASH_CPP

#include "cryptoLogging.h"
#include "cryptoHash.h"
#include <string>

using namespace std;
using namespace crypto;

/********************************************************************
    Crypto Hash
 ********************************************************************/

    //Default hash constructor
    crypto::hash::hash(uint16_t algorithm,uint16_t size)
    {
        if(size<0) size=size::hash256;
        
        _size=size;
        _algorithm=algorithm;
        _data=new unsigned char[_size];
        memset(_data,0,_size*sizeof(unsigned char));
    }
    //Copy construtor
    crypto::hash::hash(const crypto::hash& cpy)
    {
        _size=cpy._size;
        _algorithm=cpy._algorithm;
        _data=new unsigned char[_size];
        memcpy(_data,cpy._data,_size*sizeof(unsigned char));
    }
    //Equality constructor
    crypto::hash& crypto::hash::operator=(const crypto::hash& cpy)
    {
        delete [] _data;
        _size=cpy._size;
        _algorithm=cpy._algorithm;
        _data=new unsigned char[_size];
        memcpy(_data,cpy._data,_size*sizeof(unsigned char));
        return *this;
    }
    //Default destructor
    crypto::hash::~hash()
    {
        delete [] _data;
    }
    //Compares two hashes
    int crypto::hash::compare(const crypto::hash* _comp) const
    {
        if(_algorithm>_comp->_algorithm) return 1;
        else if(_algorithm<_comp->_algorithm) return-1;
        
        if(_size>_comp->_size) return 1;
        else if(_size<_comp->_size) return-1;
        
        for(uint16_t i=_size;i>0;i--)
        {
            if(_data[i-1]>_comp->_data[i-1]) return 1;
            else if(_data[i-1]<_comp->_data[i-1]) return -1;
        }
        return 0;
    }

//Operator Access----------------------------------------------------

    //Return value
    unsigned char crypto::hash::operator[](uint16_t pos) const
    {
        if(pos<0 || pos>=_size)
            return 0;
        return _data[pos];
    }
    //Set value
    unsigned char& crypto::hash::operator[](uint16_t pos)
    {
        if(pos<0 || pos>=_size)
            return _data[0];
        return _data[pos];
    }
    //Convert hash to string to output
    std::string crypto::hash::toString() const
    {
        std::string ret="";
        for(int i=0;i<_size;i++)
        {
            ret=toHex(_data[i])+ret;
        }
        return ret;
    }
    //Convert the hash from a string
    void crypto::hash::fromString(const std::string& str)
    {
    
    }
    //Output hash in stream
    std::ostream& crypto::operator<<(std::ostream& os, const crypto::hash& num)
    {
        os<<num.toString();
        return os;
    }
    //Input hash from a stream
    std::istream& crypto::operator>>(std::istream& is, crypto::hash& num)
    {
        return is;
    }

/********************************************************************
    XOR Hash
 ********************************************************************/

    //XOR hash with data and size
    xorHash::xorHash(const unsigned char* data, uint32_t length, uint16_t size):
        hash(crypto::algo::hashXOR,size)
    {
        preformHash(data,length);
    }
    //XOR hash with data (default size)
    xorHash::xorHash(const unsigned char* data, uint32_t length):
        hash(crypto::algo::hashXOR)
    {
        preformHash(data,length);
    }
    //Hash function
    void xorHash::preformHash(const unsigned char* data, uint32_t dLen)
    {
        
    }
#endif
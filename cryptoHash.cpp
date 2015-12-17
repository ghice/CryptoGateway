//Primary author: Jonathan Bedard
//Confirmed working: 12/17/2015

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
        _data=new char[_size];
        memset(_data,0,_size*sizeof(char));
    }
    //Copy construtor
    crypto::hash::hash(const crypto::hash& cpy)
    {
        _size=cpy._size;
        _algorithm=cpy._algorithm;
        _data=new char[_size];
        memcpy(_data,cpy._data,_size*sizeof(char));
    }
    //Equality constructor
    crypto::hash& crypto::hash::operator=(const crypto::hash& cpy)
    {
        delete [] _data;
        _size=cpy._size;
        _algorithm=cpy._algorithm;
        _data=new char[_size];
        memcpy(_data,cpy._data,_size*sizeof(char));
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

#endif
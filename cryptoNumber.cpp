//Primary author: Jonathan Bedard
//Confirmed working: 12/8/2015

#ifndef CRYPTO_NUMBER_CPP
#define CRYPTO_NUMBER_CPP

#include "cryptoNumber.h"

using namespace crypto;

/*================================================================
	Number
 ================================================================*/

    //Default constructor
    number::number(numberType* numDef)
    {
        _numDef=numDef;
        _size = 1;
        _data = new uint32_t[1];
        _data[0]=0;
    }
    //Size constructor
    number::number(uint16_t size, numberType* numDef)
    {
        _numDef=numDef;
        _size=size;
        if(_size<1)_size=0;
        
        _data = new uint32_t[_size];
        memset(_data,0,sizeof(uint32_t)*_size);
    }
    //Construct with data
    number::number(uint32_t* d, uint16_t size, numberType* numDef)
    {
        _numDef=numDef;
        _size=size;
        if(_size<1)_size=0;
        
        _data = new uint32_t[_size];
        if(size<1)
            memset(_data,0,sizeof(uint32_t)*_size);
        else
            memcpy(_data, d, sizeof(uint32_t)*_size);
    }
    //Copy constructor
    number::number(const number& num)
    {
        _numDef=num._numDef;
        _size=num._size;
        _data = new uint32_t[_size];
        memcpy(_data, num._data, sizeof(uint32_t)*_size);
    }
    //Destructor
    number::~number(){delete [] _data;}

//Comparison functions-------------------------------------------

    //Compare two numbers
    int number::compare(const number& num) const
    {
        uint16_t comp_len=_size;
        
        //Size mis-matches
        if(_size>num._size)
        {
            comp_len=num._size;
            for(uint16_t trc=_size-1;trc>=comp_len;trc--)
            {
                if(_data[trc]>0) return 1;
            }
        }
        else if(_size<num._size)
        {
            for(uint16_t trc=num._size-1;trc>=comp_len;trc--)
            {
                if(num._data[trc]>0) return -1;
            }
        }
        
        //Matched size
        for(uint16_t trc=comp_len-1;trc<(~(uint16_t)0);trc--)
        {
            if(_data[trc]>num._data[trc]) return 1;
            else if(_data[trc]<num._data[trc]) return -1;
        }
        return 0;
    }
    //Equality operator
    const bool number::operator==(const number& comp) const {return compare(comp)==0;}
    //Not equal operator
    const bool number::operator!=(const number& comp) const {return compare(comp)!=0;}
    //Less than or equal
    const bool number::operator<=(const number& comp) const {return compare(comp)!=1;}
    //Greater than or equal
    const bool number::operator>=(const number& comp) const {return compare(comp)!=-1;}
    //Less than
    const bool number::operator<(const number& comp) const {return compare(comp)==-1;}
    //Greater than
    const bool number::operator>(const number& comp) const {return compare(comp)==1;}

#endif
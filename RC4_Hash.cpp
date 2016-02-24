/**
 * @file    cryptoHash.cpp
 * @author  Jonathan Bedard
 * @date    2/23/2016
 * @brief   Implementation of RC4 hash
 * @bug None
 *
 * Implements the RC-4 hash algorithm.
 * The RC-4 hashing algorithm is likely
 * secure, but not proven secure.  Consult
 * the RC4_Hash.h for details.
 **/

 ///@cond INTERNAL

#ifndef RC4_HASH_CPP
#define RC4_HASH_CPP

#include "cryptoLogging.h"
#include "RC4_Hash.h"

using namespace std;
using namespace crypto;

/********************************************************************
    XOR Hash
 ********************************************************************/

    //RC-4 hash with data and size
    rc4Hash::rc4Hash(const unsigned char* data, uint32_t length, uint16_t size):
        hash(rc4Hash::staticAlgorithm(),size)
    {
        preformHash(data,length);
    }
    //RC-4 hash with data (default size)
    rc4Hash::rc4Hash(const unsigned char* data, uint16_t size):
        hash(rc4Hash::staticAlgorithm(),size)
    {
		//Acts as a copy constructor
		memcpy(_data,data,size);
    }
    //Hash function
    void rc4Hash::preformHash(const unsigned char* data, uint32_t dLen)
    {
		memset(_data,0,_size);

		int value = 0;
		int cnt = 0;
		int len;
  
		while(value<dLen)
		{
			if((dLen-value) > _size)
				len = _size;
			else
				len = dLen-value;
    
			RCFour rc((uint8_t*)&data[value], len);
			value = value+len;
    
			cnt = 0;
			while(cnt<_size)
			{
				_data[cnt] = _data[cnt]^rc.getNext();
				cnt++;
			}
		}
    }

#endif

///@endcond

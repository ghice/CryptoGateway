/**
 * @file   message.cpp
 * @author Jonathan Bedard
 * @date   3/19/2016
 * @brief  Crypto-Gateway message implementation
 * @bug No known bugs.
 *
 * Implements the message used by
 * the crypto-gateway to pass encrypted
 * data between machines.
 *
 */
 
///@cond INTERNAL
 
#ifndef MESSAGE_CPP
#define MESSAGE_CPP
    
#include "message.h"

namespace crypto {
	
	//Build an encrypted message from raw data
	message message::encryptedMessage(uint8_t* rawData,uint16_t sz)
	{
		message ret(sz);
		return ret;
	}
	//Build a decrypted message from raw data
	message message::decryptedMessage(uint8_t* rawData,uint16_t sz)
	{
		message ret(sz);
		return ret;
	}
	//Default message constructor
	message::message(uint16_t sz)
	{
		_data=new uint8_t[sz];
		memset(_data,0,sz);
		_size=sz;
		_messageSize=sz;
		_encryptionDepth=0;
	}
	//Copy constructor
	message::message(const message& msg)
	{
		_data=new uint8_t[msg._size];
		memcpy(_data,msg._data,msg._size);
		_size=msg._size;
		_messageSize=msg._messageSize;
		_encryptionDepth=msg._encryptionDepth;
	}
}

#endif

///@endcond
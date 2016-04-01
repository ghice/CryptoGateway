/**
 * @file   message.cpp
 * @author Jonathan Bedard
 * @date   4/1/2016
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
#include "gateway.h"

namespace crypto {
	
	//Build an encrypted message from raw data
	message message::encryptedMessage(uint8_t* rawData,uint16_t sz)
	{
		message ret(sz);
		if(rawData[0]==message::BLOCKED || rawData[0]==message::PING ||
			rawData[0]==message::STREAM_KEY || rawData[0]==message::BASIC_ERROR ||
			rawData[0]==message::TIMEOUT_ERROR || rawData[0]==message::PERMENANT_ERROR)
		{
			ret._messageSize=ret._messageSize-1;
		}
		else
		{
			ret._encryptionDepth=rawData[1];
			ret._messageSize=ret._messageSize-3;
		}
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
		if(sz<1) throw errorPointer(new bufferSmallError(),os::shared_type);
		_data=new uint8_t[sz];
		memset(_data,0,sz);
		_size=sz;
		_messageSize=sz-1;
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
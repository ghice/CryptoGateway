/**
 * @file   gateway.cpp
 * @author Jonathan Bedard
 * @date   3/19/2016
 * @brief  Implements the gateway
 * @bug No known bugs.
 *
 * Implements the gateway
 * defined in gateway.h.  Consult
 * gateway.h for details.
 *
 */

///@cond INTERNAL

#ifndef GATEWAY_CPP
#define GATEWAY_CPP

#include "gateway.h"
#include "cryptoError.h"

namespace crypto {
    
	//Constructs the settings from user
	gatewaySettings::gatewaySettings(os::smart_ptr<user> usr, std::string groupID, std::string filePath)
	{
		_user=usr;

		_nodeName=usr->username();
		if(_groupID.size()>size::GROUP_SIZE)
			throw errorPointer(new stringTooLarge(),os::shared_type);
		_groupID=groupID;

		update();
	}
	
	//Triggered when the public key changes
	void gatewaySettings::publicKeyChanged(os::smart_ptr<publicKey> pbk)
	{
		if(!pbk) return;
		if(pbk!=_privateKey) return;
		update();
	}
	//Update from user
	void gatewaySettings::update()
	{
		if(!_user) return;

		lock.lock();

		os::smart_ptr<publicKey> tpbk=_user->getDefaultPublicKey();
		if(!tpbk)
		{
			lock.unlock();
			throw errorPointer(new keyMissing(),os::shared_type);
		}
		if(_privateKey!=tpbk)
		{
			tpbk->keyChangeSender::pushReceivers(this);
			if(_privateKey)
				_privateKey->keyChangeSender::removeReceivers(this);
		}
		_privateKey=tpbk;
		_publicKey=_privateKey->getN();

		_prefferedPublicKeyAlgo=_privateKey->algorithm();
		_prefferedPublicKeySize=_privateKey->size();

		os::smart_ptr<streamPackageFrame> stmpkg=_user->streamPackage();
		_prefferedHashAlgo=stmpkg->hashAlgorithm();
		_prefferedHashSize=stmpkg->hashSize();
		_prefferedStreamAlgo=stmpkg->streamAlgorithm();

		lock.unlock();
	}
	
	//Construct the settings from a ping message
	gatewaySettings::gatewaySettings(const message& msg)
	{
		//Parse ping message
		if(msg.data()[0]!=message::PING)
			throw errorPointer(new customError("Non-ping Intialization",
				"Attempted to initialize gateway settings with an non-ping message"),os::shared_type);

		//Pull out group ID and node name
		uint16_t msgCount=1;

		char* arr;
		if(size::GROUP_SIZE>size::NAME_SIZE)
		{
			arr=new char[size::GROUP_SIZE+1];
			memset(arr,0,size::GROUP_SIZE+1);
		}
		else
		{
			arr=new char[size::NAME_SIZE+1];
			memset(arr,0,size::NAME_SIZE+1);
		}
		
		memcpy(arr,msg.data()+msgCount,size::GROUP_SIZE);
		msgCount+=size::GROUP_SIZE;
		_groupID=std::string(arr);
		memcpy(arr,msg.data()+msgCount,size::NAME_SIZE);
		msgCount+=size::NAME_SIZE;
		_nodeName=std::string(arr);
		delete [] arr;

		//Extract preffered record
		uint16_t temp;
		memcpy(&temp,msg.data()+msgCount,sizeof(uint16_t));
		msgCount+=sizeof(uint16_t);
		_prefferedPublicKeyAlgo=os::from_comp_mode(temp);
		memcpy(&temp,msg.data()+msgCount,sizeof(uint16_t));
		msgCount+=sizeof(uint16_t);
		_prefferedPublicKeySize=os::from_comp_mode(temp);
		memcpy(&temp,msg.data()+msgCount,sizeof(uint16_t));
		msgCount+=sizeof(uint16_t);
		_prefferedHashAlgo=os::from_comp_mode(temp);
		memcpy(&temp,msg.data()+msgCount,sizeof(uint16_t));
		msgCount+=sizeof(uint16_t);
		_prefferedHashSize=os::from_comp_mode(temp);
		memcpy(&temp,msg.data()+msgCount,sizeof(uint16_t));
		msgCount+=sizeof(uint16_t);
		_prefferedStreamAlgo=os::from_comp_mode(temp);
	}
	//Constructs a ping message
	os::smart_ptr<message> gatewaySettings::ping()
	{
		if(!_privateKey) return NULL;
		
		lock.increment();

		uint16_t msgCount=0;
		os::smart_ptr<message> png(new message(1+size::GROUP_SIZE+size::NAME_SIZE+5*sizeof(uint16_t)),os::shared_type);
		png->data()[0]=message::PING;
		msgCount+=1;
		
		//Copy in group ID and name
		memcpy(png->data()+msgCount,_groupID.c_str(),_groupID.size());
		msgCount+=size::GROUP_SIZE;
		memcpy(png->data()+msgCount,_nodeName.c_str(),_nodeName.size());
		msgCount+=size::NAME_SIZE;

		//Prefered record
		uint16_t temp;
		temp=os::to_comp_mode(_prefferedPublicKeyAlgo);
		memcpy(png->data()+msgCount,&temp,sizeof(uint16_t));
		msgCount+=sizeof(uint16_t);
		temp=os::to_comp_mode(_prefferedPublicKeySize);
		memcpy(png->data()+msgCount,&temp,sizeof(uint16_t));
		msgCount+=sizeof(uint16_t);
		temp=os::to_comp_mode(_prefferedHashAlgo);
		memcpy(png->data()+msgCount,&temp,sizeof(uint16_t));
		msgCount+=sizeof(uint16_t);
		temp=os::to_comp_mode(_prefferedHashSize);
		memcpy(png->data()+msgCount,&temp,sizeof(uint16_t));
		msgCount+=sizeof(uint16_t);
		temp=os::to_comp_mode(_prefferedStreamAlgo);
		memcpy(png->data()+msgCount,&temp,sizeof(uint16_t));
		msgCount+=sizeof(uint16_t);

		//Is technically encrypted, has no message size
		png->_encryptionDepth=1;
		png->_messageSize=0;

		lock.decrement();
		
		return png;
	}

	//Construct the gateway
    gateway::gateway()
	{
	}
	
	//Returns the key pair used for this gateway
	os::smart_ptr<publicKey> gateway::keyPair()
	{
		if(_keyPair) return _keyPair;
		return _user->getDefaultPublicKey();
	}
	
	
}

#endif

///@endcond
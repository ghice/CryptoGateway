/**
 * @file   gateway.cpp
 * @author Jonathan Bedard
 * @date   3/20/2016
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
#include "user.h"

namespace crypto {
    
	//Constructs the settings from user
	gatewaySettings::gatewaySettings(os::smart_ptr<user> usr, std::string groupID, std::string filePath)
	{
		if(!usr)
			throw errorPointer(new NULLPublicKey(),os::shared_type);
		_user=usr;

		_nodeName=usr->username();
		if(_groupID.size()>size::GROUP_SIZE)
			throw errorPointer(new stringTooLarge(),os::shared_type);
		_groupID=groupID;
		_filePath=filePath;

		_privateKey=_user->getDefaultPublicKey();
		if(!_privateKey)
			throw errorPointer(new NULLPublicKey(),os::shared_type);
		_prefferedPublicKeyAlgo=_privateKey->algorithm();
		_prefferedPublicKeySize=_privateKey->size();

		update();
		markChanged();
	}
	
	//Generate the XML save tree
	os::smartXMLNode gatewaySettings::generateSaveTree()
	{
		os::smartXMLNode ret(new os::XML_Node("gatewaySettings"),os::shared_type);

		os::smartXMLNode level1=os::smartXMLNode(new os::XML_Node("group"),os::shared_type);
		level1->setData(_groupID);
		ret->addElement(level1);

		level1=os::smartXMLNode(new os::XML_Node("name"),os::shared_type);
		level1->setData(_nodeName);
		ret->addElement(level1);

		level1=os::smartXMLNode(new os::XML_Node("preferences"),os::shared_type);
			
			os::smartXMLNode level2=os::smartXMLNode(new os::XML_Node("publicKey"),os::shared_type);
				os::smartXMLNode level3=os::smartXMLNode(new os::XML_Node("algo"),os::shared_type);
				level3->setData(std::to_string(_prefferedPublicKeyAlgo));
				level2->addElement(level3);
				level3=os::smartXMLNode(new os::XML_Node("size"),os::shared_type);
				level3->setData(std::to_string(_prefferedPublicKeySize));
				level2->addElement(level3);
			level1->addElement(level2);

			level2=os::smartXMLNode(new os::XML_Node("hash"),os::shared_type);
				level3=os::smartXMLNode(new os::XML_Node("algo"),os::shared_type);
				level3->setData(std::to_string(_prefferedHashAlgo));
				level2->addElement(level3);
				level3=os::smartXMLNode(new os::XML_Node("size"),os::shared_type);
				level3->setData(std::to_string(_prefferedHashSize));
				level2->addElement(level3);
			level1->addElement(level2);

			level2=os::smartXMLNode(new os::XML_Node("stream"),os::shared_type);
				level3=os::smartXMLNode(new os::XML_Node("algo"),os::shared_type);
				level3->setData(std::to_string(_prefferedStreamAlgo));
				level2->addElement(level3);
			level1->addElement(level2);

		ret->addElement(level1);

		return ret;
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

		os::smart_ptr<publicKeyPackageFrame> pkfrm=publicKeyTypeBank::singleton()->findPublicKey(_prefferedPublicKeyAlgo);
		os::smart_ptr<publicKey> tpbk;
		if(pkfrm)
		{
			pkfrm=pkfrm->getCopy();
			pkfrm->setKeySize(_prefferedPublicKeySize);
			tpbk=_user->findPublicKey(pkfrm);
		}
		
		//Only bind if the size is valid
		if(tpbk)
		{
			_privateKey=tpbk;
			_publicKey=_privateKey->getN();
			_publicKey->reduce();
		}
		else
		{
			_prefferedPublicKeyAlgo=_privateKey->algorithm();
			_prefferedPublicKeySize=_privateKey->size();
		}

		os::smart_ptr<streamPackageFrame> stmpkg=_user->streamPackage();
		_prefferedHashAlgo=stmpkg->hashAlgorithm();
		_prefferedHashSize=stmpkg->hashSize();
		_prefferedStreamAlgo=stmpkg->streamAlgorithm();

		lock.unlock();
	}
	//Save to file
	void gatewaySettings::save()
	{
		//Don't save if there isn't a path
		if(_filePath=="")
		{
			finishedSaving();
			return;
		}
		os::smartXMLNode nd=generateSaveTree();
		os::XML_Output(_filePath,nd);
		finishedSaving();
	}
	//Loads gateway settings from file
	void gatewaySettings::load()
	{
		if(_filePath=="") return;

		update();
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

		//Extract key
		os::smart_ptr<publicKeyPackageFrame> pkfrm=publicKeyTypeBank::singleton()->findPublicKey(_prefferedPublicKeyAlgo);
		if(pkfrm)
		{
			pkfrm=pkfrm->getCopy();
			pkfrm->setKeySize(_prefferedPublicKeySize);
			_publicKey=pkfrm->convert(msg.data()+msgCount,_prefferedPublicKeySize*sizeof(uint32_t));
		}
		msgCount+=_prefferedPublicKeySize*sizeof(uint32_t);
	}
	//Constructs a ping message
	os::smart_ptr<message> gatewaySettings::ping()
	{
		if(!_publicKey) return NULL;
		
		lock.increment();

		uint16_t msgCount=0;
		unsigned int keylen;
		os::smart_ptr<unsigned char> keyDat=_publicKey->getCompCharData(keylen);
		os::smart_ptr<message> png(new message(1+size::GROUP_SIZE+size::NAME_SIZE+
			5*sizeof(uint16_t)+keylen),os::shared_type);
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

		//Output key
		memcpy(png->data()+msgCount,keyDat.get(),keylen);
		msgCount+=keylen;

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
/**
 * @file   gateway.h
 * @author Jonathan Bedard
 * @date   3/20/2016
 * @brief  Defines the gateway
 * @bug No known bugs.
 *
 * This file contains the declartion
 * for the gateway and the gateway
 * settings.  This header file
 * is the culmination of the 
 * CryptoGateway library.
 *
 * Note that due to developement constraints,
 * the gatewaySettings class is being pushed
 * out in a frame-work form and is intended
 * to contain a large set of algorithm definitions
 * as well as an algorithm use agreement protocol.
 *
 */

#ifndef GATEWAY_H
#define GATEWAY_H
    
#include "binaryEncryption.h"
#include "cryptoLogging.h"
#include "cryptoError.h"

#include "streamPackage.h"
#include "publicKeyPackage.h"
#include "message.h"

namespace crypto {

	///@cond INTERNAL
	class user;
	///@endcond
	
	/** @brief Holds settings for gateway encryption
	 *
	 * Contains all of the information needed to define
	 * how the gateway functions.  This includes which
	 * algorithms are white-listed, which are black-
	 * listed and which are preffered.  Note that this
	 * settings class can define the settings for a node
	 * whose private key is known or for a node whose
	 * private key is unknown.
	 */
	class gatewaySettings: public keyChangeReceiver, public os::savable
	{
		std::string _groupID;
		std::string _nodeName;
		std::string _filePath;

		os::smart_ptr<user> _user;
		os::smart_ptr<publicKey> _privateKey;
		os::smart_ptr<number> _publicKey;

		uint16_t _prefferedPublicKeyAlgo;
		uint16_t _prefferedPublicKeySize;
		uint16_t _prefferedHashAlgo;
		uint16_t _prefferedHashSize;
		uint16_t _prefferedStreamAlgo;
	protected:
		void publicKeyChanged(os::smart_ptr<publicKey> pbk);
	public:
		os::multiLock lock;

		gatewaySettings(os::smart_ptr<user> usr, std::string groupID, std::string filePath);
		gatewaySettings(const message& msg);
		virtual ~gatewaySettings(){}

		os::smartXMLNode generateSaveTree();
		void update();
		void save();
		void load();

		const std::string& filePath() const {return _filePath;}
		const std::string& groupID() const {return _groupID;}
		const std::string& nodeName() const {return _nodeName;}

		inline os::smart_ptr<user> getUser() {return _user;}
		inline os::smart_ptr<publicKey> getPrivateKey() {return _privateKey;}
		inline os::smart_ptr<number> getPublicKey() {return _publicKey;}

		inline uint16_t prefferedPublicKeyAlgo() const {return _prefferedPublicKeyAlgo;}
		inline uint16_t prefferedPublicKeySize() const {return _prefferedPublicKeySize;}
		inline uint16_t prefferedHashAlgo() const {return _prefferedHashAlgo;}
		inline uint16_t prefferedHashSize() const {return _prefferedHashSize;}
		inline uint16_t prefferedStreamAlgo() const {return _prefferedStreamAlgo;}

		os::smart_ptr<message> ping();

		bool operator==(const gatewaySettings& cmp) const{return _groupID==cmp._groupID;}
		bool operator!=(const gatewaySettings& cmp) const{return _groupID!=cmp._groupID;}
		bool operator<(const gatewaySettings& cmp) const{return _groupID<cmp._groupID;}
		bool operator>(const gatewaySettings& cmp) const{return _groupID>cmp._groupID;}
		bool operator<=(const gatewaySettings& cmp) const{return _groupID<=cmp._groupID;}
		bool operator>=(const gatewaySettings& cmp) const{return _groupID>=cmp._groupID;}
	};

	class gateway
	{
		os::smart_ptr<user> _user;
		std::string _groupID;
		
		os::smart_ptr<publicKey> _keyPair;
	public:
		gateway();
		virtual ~gateway(){}
		
		os::smart_ptr<publicKey> keyPair();
	};

}

#endif

/**
 * @file   gateway.h
 * @author Jonathan Bedard
 * @date   3/19/2016
 * @brief  Defines the gateway
 * @bug No known bugs.
 *
 * This file contains the declartion
 * for the gateway and the gateway
 * settings.  This header file
 * is the culmination of the 
 * CryptoGateway library.
 *
 */

#ifndef GATEWAY_H
#define GATEWAY_H
    
#include "binaryEncryption.h"
#include "cryptoLogging.h"
#include "cryptoError.h"

#include "streamPackage.h"
#include "publicKeyPackage.h"
#include "user.h"
#include "message.h"

namespace crypto {
	
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
	class gatewaySettings: public keyChangeReceiver
	{
		std::string _groupID;
		std::string _nodeName;

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

		void update();

		virtual ~gatewaySettings(){}

		const std::string& groupID() const {return _groupID;}
		const std::string& nodeName() const {return _nodeName;}

		inline uint16_t prefferedPublicKeyAlgo() const {return _prefferedPublicKeyAlgo;}
		inline uint16_t prefferedPublicKeySize() const {return _prefferedPublicKeySize;}
		inline uint16_t prefferedHashAlgo() const {return _prefferedHashAlgo;}
		inline uint16_t prefferedHashSize() const {return _prefferedHashSize;}
		inline uint16_t prefferedStreamAlgo() const {return _prefferedStreamAlgo;}

		os::smart_ptr<message> ping();

		inline bool operator==(const gatewaySettings& cmp) const{return _groupID==cmp._groupID;}
		inline bool operator!=(const gatewaySettings& cmp) const{return _groupID!=cmp._groupID;}
		inline bool operator<(const gatewaySettings& cmp) const{return _groupID<cmp._groupID;}
		inline bool operator>(const gatewaySettings& cmp) const{return _groupID>cmp._groupID;}
		inline bool operator<=(const gatewaySettings& cmp) const{return _groupID<=cmp._groupID;}
		inline bool operator>=(const gatewaySettings& cmp) const{return _groupID>=cmp._groupID;}
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

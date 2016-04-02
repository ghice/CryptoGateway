/**
 * @file   gateway.h
 * @author Jonathan Bedard
 * @date   4/1/2016
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
		/** @brief
		 */
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

	class gateway: public errorSender
	{
	public:
		static const uint64_t DEFAULT_TIMEOUT=60;
		static const uint64_t DEFAULT_ERROR_TIMEOUT=30;

		static const uint8_t UNKNOWN_STATE=0;
		static const uint8_t UNKNOWN_BROTHER=1;
		static const uint8_t SETTINGS_EXCHANGED=2;
		static const uint8_t ESTABLISHING_STREAM=3;
		static const uint8_t STREAM_ESTABLISHED=4;
		static const uint8_t SIGNING_STATE=5;
		static const uint8_t CONFIRM_OLD=6;
		static const uint8_t ESTABLISHED=7;

		static const uint8_t CONFIRM_ERROR_STATE=252;
		static const uint8_t BASIC_ERROR_STATE=253;
		static const uint8_t TIMEOUT_ERROR_STATE=254;
		static const uint8_t PERMENANT_ERROR_STATE=255;
	private:
		os::smart_ptr<gatewaySettings> selfSettings;
		os::smart_ptr<gatewaySettings> brotherSettings;
		os::spinLock lock;
		os::spinLock stampLock;

		uint8_t _currentState;
		uint8_t _brotherState;

		errorPointer _lastError;
		uint8_t _lastErrorLevel;
		uint64_t _errorTimestamp;

		uint64_t _timeout;
		uint64_t _safeTimeout;
		uint64_t _errorTimeout;
		uint64_t _messageReceived;
		uint64_t _messageSent;

		//Public keys and algorithm definitions
		os::smart_ptr<streamPackageFrame> selfStream;
		os::smart_ptr<publicKeyPackageFrame> selfPKFrame;
		os::smart_ptr<publicKey> selfPublicKey;
		os::smart_ptr<number> selfPreciseKey;

		os::smart_ptr<streamPackageFrame> brotherStream;
		os::smart_ptr<publicKeyPackageFrame> brotherPKFrame;
		os::smart_ptr<number> brotherPublicKey;

		//Stream establishing
		os::smart_ptr<message> streamMessageIn;
		os::smart_ptr<streamDecrypter> inputStream;
		
		uint64_t streamEstTimestamp;
		os::smart_ptr<message> streamMessageOut;
		os::smart_ptr<streamEncrypter> outputStream;

		//Signatures
		os::smart_ptr<uint8_t> outputHashArray;
		uint16_t outputHashLength;
		os::smart_ptr<hash> selfPrimarySignatureHash;
		os::smart_ptr<hash> selfSecondarySignatureHash;
		os::smart_ptr<message> selfSigningMessage;

		os::smart_ptr<uint8_t> inputHashArray;
		uint16_t inputHashLength;
		os::smart_ptr<hash> brotherPrimarySignatureHash;
		os::smart_ptr<hash> brotherSecondarySignatureHash;
		os::smart_ptr<message> brotherSigningMessage;

		void clearStream();
		void buildStream();

		os::smart_ptr<message> encrypt(os::smart_ptr<message> msg);
		os::smart_ptr<message> decrypt(os::smart_ptr<message> msg);

		void purgeLastError();

	protected:
		void logError(errorPointer elm,uint8_t errType);
		void logError(errorPointer elm) {logError(elm,BASIC_ERROR_STATE);}
	public:
		gateway(os::smart_ptr<user> usr,std::string groupID="default");
		virtual ~gateway(){}
		
		os::smart_ptr<message> getMessage();
		os::smart_ptr<message> ping();
		os::smart_ptr<message> processMessage(os::smart_ptr<message> msg);
		void processTimestamps();

		inline uint8_t currentState() const {return _currentState;}
		inline uint8_t brotherState() const {return _brotherState;}

		inline bool secure() const {return _currentState==ESTABLISHED;}


		uint64_t timeout() const {return _timeout;}
		uint64_t safeTimeout() const {return _safeTimeout;}
		uint64_t errorTimeout() const {return _errorTimeout;}
		uint64_t timeMessageReceived() const {return _messageReceived;}
		uint64_t timeMessageSent() const {return _messageSent;}
		uint64_t timeLastError() const {return _errorTimestamp;}
	};

}

#endif

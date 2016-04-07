/**
 * @file   gateway.h
 * @author Jonathan Bedard
 * @date   4/6/2016
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
		/** @brief Group ID of the node, unique to this settings class
		 */
		std::string _groupID;
		/** @brief Name of the node, defined by the user
		 */
		std::string _nodeName;
		/** @brief Save file path
		 *
		 * If the setting was defined by the user and
		 * not a "ping" message, it will often have a
		 * save file location.
		 */
		std::string _filePath;

		/** @brief Pointer to the user class
		 */
		os::smart_ptr<user> _user;
		/** @brief Pointer to public/private key pair
		 */
		os::smart_ptr<publicKey> _privateKey;
		/** @brief Pointer to the public key
		 */
		os::smart_ptr<number> _publicKey;

		/** @brief Public key algorithm ID
		 */
		uint16_t _prefferedPublicKeyAlgo;
		/** @brief Public key size (uint32_t size)
		 */
		uint16_t _prefferedPublicKeySize;
		/** @brief Hash algorithm ID
		 */
		uint16_t _prefferedHashAlgo;
		/** @brief Hash size (in bytes)
		 */
		uint16_t _prefferedHashSize;
		/** @brief Stream algorithm ID
		 */
		uint16_t _prefferedStreamAlgo;
	protected:
		/** @brief Triggered when the public key is changed
		 *
		 * Updates the gateway settings when the user indicates
		 * a public key has been updated.
		 *
		 * @param [in] pbk Updated public/private key pair
		 * @return void
		 */
		void publicKeyChanged(os::smart_ptr<publicKey> pbk);
	public:
		/** @brief Read/write mutex
		 *
		 * When this class is defined by a user, it is
		 * possible for the user to change the gateway
		 * settings during runtime.  Because of this,
		 * a read/write lock is required.
		 */
		os::multiLock lock;

		/** @brief User constructor
		 *
		 * Constructs the class from a user.  While this
		 * constructor can be called ouside the user class,
		 * it is suggested to use the interface provided in
		 * crypto::user to create new gateway settings.
		 *
		 * @param [in] usr User defining the settings
		 * @param [in] groupID Group ID of the settings
		 * @param [in] filePath Save file location (optional)
		 */
		gatewaySettings(os::smart_ptr<user> usr, std::string groupID, std::string filePath="");
		/** @brief Ping message constructor
		 *
		 * Constructs the gateway settings from a ping message.
		 * This is usually used by the gateway to parse ping messages
		 * it receives.
		 *
		 * @param [in] msg Ping message
		 */
		gatewaySettings(const message& msg);
		/** @brief Virtual destructor
         *
         * Destructor must be virtual, if an object
         * of this type is deleted, the destructor
         * of the type which inherits this class should
         * be called.
         */
		virtual ~gatewaySettings();

		/** @brief Generate XML save stree
		 * @return XML save tree
		 */
		os::smartXMLNode generateSaveTree();
		/** @brief Ensure preffered algorithms are defined
		 *
		 * Uses current information in the class to determine
		 * if known algorithms define the preffered algorithms
		 * in this class.  If the preffered algorithms are not
		 * defined, they are changed to defined algorithms.
		 *
		 * @return void
		 */
		void update();
		/** @brief Saves the class to a file
		 * Saves the settings to an XML file,
		 * if the file path is defined.
		 * @return void
		 */
		void save();
		/** @brief Loads the class from a file
		 * Loads the settings from an XML file,
		 * if the file path is defined.
		 * @return void
		 */
		void load();

		/** @brief Return reference to the file path
		 * @return gatewaySettings::_filePath
		 */
		const std::string& filePath() const {return _filePath;}
		/** @brief Return reference to the group ID
		 * @return gatewaySettings::_groupID
		 */
		const std::string& groupID() const {return _groupID;}
		/** @brief Return reference to the node name
		 * @return gatewaySettings::_nodeName
		 */
		const std::string& nodeName() const {return _nodeName;}

		/** @brief Return user, if it is defined
		 * @return gatewaySettings::_user
		 */
		inline os::smart_ptr<user> getUser() {return _user;}
		/** @brief Return public/private key pair, if it is defined
		 * @return gatewaySettings::_privateKey
		 */
		inline os::smart_ptr<publicKey> getPrivateKey() {return _privateKey;}
		/** @brief Return public key
		 * @return gatewaySettings::_publicKey
		 */
		inline os::smart_ptr<number> getPublicKey() {return _publicKey;}

		inline uint16_t prefferedPublicKeyAlgo() const {return _prefferedPublicKeyAlgo;}
		inline uint16_t prefferedPublicKeySize() const {return _prefferedPublicKeySize;}
		inline uint16_t prefferedHashAlgo() const {return _prefferedHashAlgo;}
		inline uint16_t prefferedHashSize() const {return _prefferedHashSize;}
		inline uint16_t prefferedStreamAlgo() const {return _prefferedStreamAlgo;}

		/** @brief Construct a ping message
		 * @return New ping message
		 */
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
		os::unsortedList<hash> eligibleKeys;

		os::smart_ptr<uint8_t> inputHashArray;
		uint16_t inputHashLength;
		os::smart_ptr<hash> brotherPrimarySignatureHash;
		os::smart_ptr<hash> brotherSecondarySignatureHash;
		os::smart_ptr<message> brotherSigningMessage;
		

		void clearStream();
		void buildStream();

		os::smart_ptr<message> encrypt(os::smart_ptr<message> msg);
		os::smart_ptr<message> decrypt(os::smart_ptr<message> msg);
		os::smart_ptr<message> currentError();

		void purgeLastError();

	protected:
		void logError(errorPointer elm,uint8_t errType);
		void logError(errorPointer elm) {logError(elm,BASIC_ERROR_STATE);}
	public:
		gateway(os::smart_ptr<user> usr,std::string groupID="default");
		virtual ~gateway(){}
		
		os::smart_ptr<message> getMessage();
		os::smart_ptr<message> send(os::smart_ptr<message> msg);
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

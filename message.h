/**
 * @file   message.h
 * @author Jonathan Bedard
 * @date   4/1/2016
 * @brief  Crypto-Gateway message
 * @bug No known bugs.
 *
 * The message declared in this
 * file acts as a message for
 * the Crypto-Gateway.  These messages
 * are intended to be converted to
 * machine-to-machine communication.
 *
 */

#ifndef MESSAGE_H
#define MESSAGE_H
    
#include "Datastructures.h"

namespace crypto {
	
	///@cond INTERNAL
	class gatewaySettings;
	class gateway;
	///@endcond
	
	/** @brief Crypto-Gateway message
	 *
	 * This message is meant to be
	 * passed between machines.  The
	 * gateway either encrypts or
	 * decrypts the message.  This message
	 * allows for nested encryption.
	 */
	class message
	{
		friend class gatewaySettings;
		friend class gateway;

		uint16_t _messageSize;
		uint16_t _size;
		uint16_t _encryptionDepth;
		
		uint8_t* _data;
	public:
		static message encryptedMessage(uint8_t* rawData,uint16_t sz);
		static message decryptedMessage(uint8_t* rawData,uint16_t sz);
	
		message(uint16_t sz);
		message(const message& msg);
		
		virtual ~message(){delete [] _data;}
		
		inline uint16_t messageSize() const {return _messageSize;}
		inline uint16_t size() const {return _size;}
		inline uint16_t encryptionDepth() const {return _encryptionDepth;}
		inline uint8_t* data() {return _data;}
		inline const uint8_t* data() const {return _data;}
		inline bool encrypted() const {return _encryptionDepth;}
		
		static const uint8_t BLOCKED=0;
		static const uint8_t PING=1;
		static const uint8_t FORWARD=2;
		static const uint8_t STREAM_KEY=3;
		static const uint8_t SIGNING_MESSAGE=4;

		static const uint8_t CONFIRM_ERROR=252;
		static const uint8_t BASIC_ERROR=253;
		static const uint8_t TIMEOUT_ERROR=254;
		static const uint8_t PERMENANT_ERROR=255;
	};
}

#endif

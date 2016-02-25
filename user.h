/**
 * @file	user.h
 * @author	Jonathan Bedard
 * @date   	2/24/2016
 * @brief	Definition of the CryptoGateway user
 * @bug	None
 *
 * Provides a definition of user which
 * has a user-name, password and associated
 * bank of public keys.
 **/

#ifndef USER_H
#define USER_H
    
#include "binaryEncryption.h"
#include "cryptoLogging.h"
#include "cryptoError.h"

#include "streamPackage.h"
#include "publicKeyPackage.h"

namespace crypto {
  
	/** @brief Primary user class
	 *
	 * The user class defines a set of keys
	 * associated with a local user.  This class
	 * notifies a set of listeners when various
	 * passwords and keys are changed, as this
	 * class allows for the encryption of a group
	 * of files with the provided keys
	 */
	class user
	{
	protected:
		/** @brief Name of user
		 */
		std::string _username;
		/** @brief Primary symmetric key
		 */
		unsigned char* _password;
		/** @brief Length of symmetric key
		 */
		unsigned int _passwordLength;
		/** @brief Save directory for user
		 */
		std::string _saveDir;
	public:
		/** @brief Constructs the user from scratch or directory
		 *
		 * Constructs a user from a directory or from scratch.
		 * If the specified directory does not exists, this
		 * class creates the directory and begins to populate
		 * it.  If no key is specified, all files are un-encrypted.
		 * If a key is specified, all files are encrypted with this
		 * key.
		 * 
		 */
		user(std::string username,std::string saveDir="",const unsigned char* key=NULL,unsigned int keyLen=0);
		/** @brief
		 */
		virtual ~user();
		
		/** @brief Saves all dependencies
		 *
		 * This function saves all dependencies
		 * based on the save queue.
		 * @return void
		 */
		void save();
		
		/** @brief Access name of user
		 * @return crypto::user::_username
		 */
		const std::string& username() const {return _username;}
		/** @brief Access raw password
		 * @return crypto::user::_password
		 */
		const unsigned char* password() const {return _password;}
		/** @brief Access password length
		 * @return crypto::user::_passwordLength
		 */
		unsigned int passwordLength() const {return _passwordLength;}

	};
}

#endif

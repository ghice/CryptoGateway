/**
 * @file	user.h
 * @author	Jonathan Bedard
 * @date   	2/28/2016
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
#include "keyBank.h"

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
    class user: public os::savingGroup,public errorSender
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
        
        /** @brief Default stream package
         */
        os::smart_ptr<streamPackageFrame> _streamPackage;
        /** @brief Key bank 
		 *
		 * This key bank defines all of the public
		 * keys which are known by this user
		 */
		os::smart_ptr<keyBank> _keyBank;

        /** @brief Creates meta-data XML file
         *
         * Constructs and returns the XML tree
         * for this class.  The XML tree may
         * or may not be encrypted.
         *
         * @return XML tree for saving
         */
        os::smartXMLNode generateSaveTree();
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
		 * @param [in] username Name of user to be saved
		 * @param [in] saveDir Directory to save users in
		 * @param [in] key Symetric key
		 * @param [in] keyLen Length of symetric key
		 * 
		 */
		user(std::string username,std::string saveDir="",const unsigned char* key=NULL,unsigned int keyLen=0);
		/** @brief Virtual destructor
         *
         * Destructor must be virtual, if an object
         * of this type is deleted, the destructor
         * of the type which inherits this class should
         * be called.
         */
		virtual ~user();
		
		/** @brief Saves all dependencies
		 *
		 * This function saves all dependencies
		 * based on the save queue.
		 * @return void
		 */
		void save();
		
	//Set Data-----------------------------------------------------------

		/** @brief Set password
		 *
		 * Sets symetric key used to securely
		 * save user data.
		 *
		 * @param [in] key Symetric key
		 * @param [in] keyLen Length of symetric key
		 *
		 * @return void
		 */
		void setPassword(const unsigned char* key=NULL,unsigned int keyLen=0);
		/** @brief Set stream package
		 *
		 * Binds a new stream package.  Calls
		 * for saving of this user.
		 *
		 * @param [in] strmPack Stream package
		 *
		 * @return void
		 */
		void setStreamPackage(os::smart_ptr<streamPackageFrame> strmPack);

	//Access-------------------------------------------------------------

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
		/** @brief Access streaming package
		 * @return crypto::user::_streamPackage
		 */
		os::smart_ptr<streamPackageFrame> streamPackage() const {return _streamPackage;}
		/** @brief Access key bank
		 * @return crypto::user::_keyBank
		 */
		os::smart_ptr<streamPackageFrame> getKeyBank() const {return _keyBank;}

	};
}

#endif

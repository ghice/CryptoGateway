/**
 * @file	user.cpp
 * @author	Jonathan Bedard
 * @date   	2/24/2016
 * @brief	Implementation of the CryptoGateway user
 * @bug	None
 *
 * Provides an implementation of user which
 * has a user-name, password and associated
 * bank of public keys.  Consult user.h for
 * details.
 **/
 
 ///@cond INTERNAL

#ifndef USER_CPP
#define USER_CPP

#include "user.h"

namespace crypto {
    
/*-----------------------------------
     User Constructor
  -----------------------------------*/

	//User constructor
	user::user(std::string username,std::string saveDir,const unsigned char* key,unsigned int keyLen)
	{
		//Basic initializers
		_username=username;
		_saveDir=saveDir;
		if(key==NULL || keyLen==0)
		{
			_password=NULL;
			_passwordLength=0;
		}
		else
		{
			_password=new unsigned char[keyLen];
			memcpy(_password,key,keyLen);
			_passwordLength=keyLen;
		}

		//Check to see if the directory exists
		if(_saveDir=="") return;
		
	}
	//Tear down, attempt a save first
	user::~user()
	{
		save();
		if(_password!=NULL) delete [] _password;
	}
	//Save all data
	void user::save()
	{
		//No directory, saving is disabled
		if(_saveDir=="") return;

		//Save self first
	}
}

#endif

///@endcond
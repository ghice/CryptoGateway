/**
 * @file	user.cpp
 * @author	Jonathan Bedard
 * @date   	2/28/2016
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

#define META_FILE "metaData.xml"
#define KEY_BANK_FILE "keyBank.xml"

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
        _streamPackage=streamPackageTypeBank::singleton()->defaultPackage();

		//Unsavable key bank
		_keyBank=os::smart_ptr<keyBank>(new avlKeyBank(),os::shared_type);
		bindSavable(os::cast<os::savable,keyBank>(_keyBank));

		//Check key size
		if(keyLen>size::STREAM_SEED_MAX)
		{
			logError(errorPointer(new passwordLargeError(),os::shared_type));
			keyLen=size::STREAM_SEED_MAX;
		}

		//Copy key
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

		//Check to see if the username exists
		if(_username=="")
		{
			logError(errorPointer(new customError("No username","No username was bound to this user."),os::shared_type));
			return;
		}

		//Check to see if the directory exists
		if(_saveDir=="") return;
		markChanged();
        
        //Check if directory exists
        os::testCreateFolder(_saveDir);
        os::testCreateFolder(_saveDir+"/"+_username);
        
        //Load files
        
		//Meta data read
		os::smartXMLNode readTree=os::XML_Input(_saveDir+"/"+_username+"/"+META_FILE);
		os::smartXMLNodeList xmlList;
		
		//Only relevant if the file existed
		if(readTree)
		{
			if(readTree->getID()!="userData")
			{
				logError(errorPointer(new fileFormatError(),os::shared_type));
				return;
			}

			//Stream package
			{
				xmlList=readTree->findElement("streamPackage");
				if(xmlList->size()!=1)
				{
					logError(errorPointer(new fileFormatError(),os::shared_type));
					return;
				}
				os::smartXMLNode stmpckg=xmlList->getFirst()->getData();

				//Stream algorithm
				xmlList=stmpckg->findElement("stream");
				if(xmlList->size()!=1)
				{
					logError(errorPointer(new fileFormatError(),os::shared_type));
					return;
				}
				std::string strStreamAlgo=xmlList->getFirst()->getData()->getData();

				//Hash
				xmlList=stmpckg->findElement("hash");
				if(xmlList->size()!=1)
				{
					logError(errorPointer(new fileFormatError(),os::shared_type));
					return;
				}
				os::smartXMLNode hshNode=xmlList->getFirst()->getData();
				xmlList=hshNode->findElement("algo");
				if(xmlList->size()!=1)
				{
					logError(errorPointer(new fileFormatError(),os::shared_type));
					return;
				}
				std::string strHashAlgo=xmlList->getFirst()->getData()->getData();
				xmlList=hshNode->findElement("size");
				if(xmlList->size()!=1)
				{
					logError(errorPointer(new fileFormatError(),os::shared_type));
					return;
				}
				int intHashSize;
				try
				{
					intHashSize=std::stoi(xmlList->getFirst()->getData()->getData())/8;
				}
				catch(...)
				{
					logError(errorPointer(new fileFormatError(),os::shared_type));
					return;
				}

				//Set stream package
				_streamPackage=streamPackageTypeBank::singleton()->findStream(strStreamAlgo,strHashAlgo);
				if(!_streamPackage)
					_streamPackage=streamPackageTypeBank::singleton()->defaultPackage();
				_streamPackage=_streamPackage->getCopy();
				_streamPackage->setHashSize(intHashSize);
			}

			//Check name/password
			{
				xmlList=readTree->findElement("user");
				if(xmlList->size()!=1)
				{
					logError(errorPointer(new fileFormatError(),os::shared_type));
					return;
				}
				os::smartXMLNode usrDat=xmlList->getFirst()->getData();

				//Check username
				xmlList=usrDat->findElement("name");
				if(xmlList->size()!=1)
				{
					logError(errorPointer(new fileFormatError(),os::shared_type));
					return;
				}
				if(xmlList->getFirst()->getData()->getData()!=_username)
				{
					logError(errorPointer(new customError("Username Mis-match","Constructed username and saved username do not match"),os::shared_type));
					return;
				}

				//Check password
				xmlList=usrDat->findElement("password");
				if(xmlList->size()!=1)
				{
					logError(errorPointer(new fileFormatError(),os::shared_type));
					return;
				}
				if(xmlList->getFirst()->getData()->getData()=="NULL")
				{
					if(_password!=NULL)
					{
						logError(errorPointer(new hashCompareError(),os::shared_type));
						return;
					}
				}
				else
				{
					if(_password==NULL)
					{
						logError(errorPointer(new hashCompareError(),os::shared_type));
						return;
					}
					hash hshFile=_streamPackage->hashEmpty();
					hshFile.fromString(xmlList->getFirst()->getData()->getData());
					hash hshPass=_streamPackage->hashData(_password,_passwordLength);
					if(hshFile!=hshPass)
					{
						logError(errorPointer(new hashCompareError(),os::shared_type));
						return;
					}
				}
			}
		}

		//Load Key bank
		_keyBank=os::smart_ptr<keyBank>(new avlKeyBank(_saveDir+"/"+_username+"/"+KEY_BANK_FILE,_password,_passwordLength,_streamPackage),os::shared_type);
		bindSavable(os::cast<os::savable,keyBank>(_keyBank));
	}
	//Tear down, attempt a save first
	user::~user()
	{
		if(needsSaving()) save();
		if(_password!=NULL) delete [] _password;
	}
    //Generate an XML tree for saving
    os::smartXMLNode user::generateSaveTree()
    {
		os::smartXMLNode ret(new os::XML_Node("userData"),os::shared_type);
        os::smartXMLNode lv1(new os::XML_Node("streamPackage"),os::shared_type);
        
		//Stream
		os::smartXMLNode lv2(new os::XML_Node("stream"),os::shared_type);
		lv2->setData(_streamPackage->streamAlgorithmName());
        lv1->addElement(lv2);

		//Hash
		lv2=os::smartXMLNode(new os::XML_Node("hash"),os::shared_type);
		os::smartXMLNode lv3(new os::XML_Node("algo"),os::shared_type);
		lv3->setData(_streamPackage->hashAlgorithmName());
		lv2->addElement(lv3);
		lv3=os::smartXMLNode(new os::XML_Node("size"),os::shared_type);
		lv3->setData(std::to_string(_streamPackage->hashSize()*8));
		lv2->addElement(lv3);

        lv1->addElement(lv2);
		ret->addElement(lv1);

		//User
		lv1=os::smartXMLNode(new os::XML_Node("user"),os::shared_type);

        //Name
        lv2=os::smartXMLNode(new os::XML_Node("name"),os::shared_type);
        lv2->setData(_username);
        lv1->addElement(lv2);
        
        //Password hash
        lv2=os::smartXMLNode(new os::XML_Node("password"),os::shared_type);
        if(_password==NULL) lv2->setData("NULL");
        else
        {
            hash hsh=_streamPackage->hashData(_password, _passwordLength);
            lv2->setData(hsh.toString());
        }
        lv1->addElement(lv2);
        ret->addElement(lv1);

        return ret;
    }
	//Save all data
	void user::save()
	{
		//No directory, saving is disabled
		if(_saveDir=="" || _username=="")
        {
            errorSaving("No save directory");
            return;
        }
        if(!needsSaving()) return;

		//Save self first
        os::smartXMLNode svTree=generateSaveTree();
        os::XML_Output(_saveDir+"/"+_username+"/"+META_FILE, svTree);
        
        //Save all listeners
        os::savingGroup::save();
	}

/*-----------------------------------
	Set Data
  -----------------------------------*/

	//Sets password
	void user::setPassword(const unsigned char* key,unsigned int keyLen)
	{
		//Set key
		if(_password!=NULL)
			delete [] _password;

		//Check key size
		if(keyLen>size::STREAM_SEED_MAX)
		{
			logError(errorPointer(new passwordLargeError(),os::shared_type));
			keyLen=size::STREAM_SEED_MAX;
		}

		//Copy key
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

		//Set keybank
		_keyBank->setPassword(_password,_passwordLength);

		markChanged();
	}
	//Set stream package
	void user::setStreamPackage(os::smart_ptr<streamPackageFrame> strmPack)
	{
		_streamPackage=strmPack->getCopy();
		_keyBank->setStreamPackage(_streamPackage);

		markChanged();
	}
}

#endif

///@endcond
/**
 * @file	user.cpp
 * @author	Jonathan Bedard
 * @date   	3/12/2016
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
#define PUBLIC_KEY_FILE "publicKey.bin"
#define BLOCK_SIZE 20

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
		_wasConstructed=false;
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
		if(_saveDir=="")
		{
			_wasConstructed=true;
			return;
		}
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

			//Pull public keys
			{
				//Super-holder first
				xmlList=readTree->findElement("publicKeys");
				if(xmlList->size()!=1)
				{
					logError(errorPointer(new fileFormatError(),os::shared_type));
					return;
				}
				os::smartXMLNode pubKeys=xmlList->getFirst()->getData();

				//List of nodes
				xmlList=pubKeys->findElement("list");
				if(xmlList->size()!=1)
				{
					logError(errorPointer(new fileFormatError(),os::shared_type));
					return;
				}
				os::smartXMLNode nodeList=xmlList->getFirst()->getData();
				xmlList=nodeList->findElement("node");

				//Seed password
				os::smart_ptr<unsigned char> streamArr;
				if(_password!=NULL && _passwordLength>0)
				{
					os::smart_ptr<streamCipher> strm = _streamPackage->buildStream(_password,_passwordLength);
					streamArr=os::smart_ptr<unsigned char>(new unsigned char[BLOCK_SIZE*xmlList->size()],os::shared_type_array);
					for(unsigned int i=0;i<BLOCK_SIZE*xmlList->size();i++)
						streamArr[i]=strm->getNext();
				}

				//Iterate through all nodes
				unsigned int trc=0;
				for(auto it=xmlList->getFirst();it;it=it->getNext())
				{
					std::string publicKeyName;
					std::string algoNameTemp;
					os::smartXMLNodeList tempList=it->getData()->findElement("algo");
					if(tempList->size()!=1)
					{
						logError(errorPointer(new fileFormatError(),os::shared_type));
						return;
					}
					algoNameTemp=tempList->getFirst()->getData()->getData();
					publicKeyName=algoNameTemp;
					tempList=it->getData()->findElement("size");
					if(tempList->size()!=1)
					{
						logError(errorPointer(new fileFormatError(),os::shared_type));
						return;
					}
					publicKeyName+="_"+tempList->getFirst()->getData()->getData();
					publicKeyName+="_"+std::string(PUBLIC_KEY_FILE);
					
					//Load new key
					os::smart_ptr<publicKeyPackageFrame> pkFrame=publicKeyTypeBank::singleton()->findPublicKey(algoNameTemp);
					if(!pkFrame) logError(errorPointer(new illegalAlgorithmBind(algoNameTemp),os::shared_type));
					else
					{
						os::smart_ptr<publicKey> tpk;
						try
						{
							if(streamArr)
								tpk=pkFrame->openFile(_saveDir+"/"+_username+"/"+publicKeyName,streamArr.get()+trc*BLOCK_SIZE,BLOCK_SIZE);
							else
								tpk=pkFrame->openFile(_saveDir+"/"+_username+"/"+publicKeyName,"");
							if(!tpk) throw errorPointer(new NULLPublicKey(),os::shared_type);

							if(!_publicKeys.insert(tpk)) throw errorPointer(new NULLPublicKey(),os::shared_type);
							bindSavable(os::cast<os::savable,publicKey>(tpk));
							tpk->setEncryptionAlgorithm(_streamPackage);
						}
						catch(errorPointer e)
						{
							logError(e);
						}
						catch(...)
						{
							logError(errorPointer(new unknownErrorType(),os::shared_type));
						}
					}
					trc++;
				}

				//Default public key
				if(_publicKeys.size()>0)
				{
					xmlList=pubKeys->findElement("default");
					if(xmlList->size()!=1)
					{
						logError(errorPointer(new fileFormatError(),os::shared_type));
						return;
					}
					os::smartXMLNode defNode=xmlList->getFirst()->getData();

					//Algorithm
					xmlList=defNode->findElement("algo");
					if(xmlList->size()!=1)
					{
						logError(errorPointer(new fileFormatError(),os::shared_type));
						return;
					}
					std::string defStr=xmlList->getFirst()->getData()->getData();

					//Algorithm
					xmlList=defNode->findElement("size");
					if(xmlList->size()!=1)
					{
						logError(errorPointer(new fileFormatError(),os::shared_type));
						return;
					}
					unsigned int defSize;
					try
					{
						defSize=std::stoi(xmlList->getFirst()->getData()->getData())/32;
						os::smart_ptr<publicKeyPackageFrame> pkFrame=publicKeyTypeBank::singleton()->findPublicKey(defStr);
						pkFrame->setKeySize(defSize);
						os::smart_ptr<publicKey> pk=findPublicKey(pkFrame);
						if(!pk) throw -1;
						setDefaultPublicKey(pk);
					}
					catch(...)
					{
						logError(errorPointer(new fileFormatError(),os::shared_type));
						if(_publicKeys.getFirst())
							setDefaultPublicKey(_publicKeys.getFirst()->getData());
					}
				}
			}
		}

		//Load Key bank
		_keyBank=os::smart_ptr<keyBank>(new avlKeyBank(_saveDir+"/"+_username+"/"+KEY_BANK_FILE,_password,_passwordLength,_streamPackage),os::shared_type);
		if(_defaultKey)
			_keyBank->setPublicKey(_defaultKey);
		bindSavable(os::cast<os::savable,keyBank>(_keyBank));
		_wasConstructed=true;
	}
	//Tear down, attempt a save first
	user::~user()
	{
		if(_wasConstructed && numberErrors()==0 && needsSaving()) save();
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

		//Public keys
		lv1=os::smartXMLNode(new os::XML_Node("publicKeys"),os::shared_type);
		lv2=os::smartXMLNode(new os::XML_Node("default"),os::shared_type);
		lv3=os::smartXMLNode(new os::XML_Node("algo"),os::shared_type);
		if(_defaultKey==NULL) lv3->setData("NULL");
		else lv3->setData(_defaultKey->algorithmName());
		lv2->addElement(lv3);
		lv3=os::smartXMLNode(new os::XML_Node("size"),os::shared_type);
		if(_defaultKey==NULL) lv3->setData("NULL");
		else lv3->setData(std::to_string(_defaultKey->size()*32));
		lv2->addElement(lv3);

		lv1->addElement(lv2);
		lv2=os::smartXMLNode(new os::XML_Node("list"),os::shared_type);
		for(auto it=_publicKeys.getFirst();it;it=it->getNext())
		{
			lv3=os::smartXMLNode(new os::XML_Node("node"),os::shared_type);
			os::smartXMLNode lv4(new os::XML_Node("algo"),os::shared_type);
			lv4->setData(it->getData()->algorithmName());
			lv3->addElement(lv4);
			lv4=os::smartXMLNode(new os::XML_Node("size"),os::shared_type);
			lv4->setData(std::to_string(it->getData()->size()*32));
			lv3->addElement(lv4);
			lv2->addElement(lv3);
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
		if(_wasConstructed)
		{
			os::smartXMLNode svTree=generateSaveTree();
			os::XML_Output(_saveDir+"/"+_username+"/"+META_FILE, svTree);
		}
        
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

		//Public keys
		if(_password!=NULL && _passwordLength>0 && _publicKeys.size()>0)
		{
			os::smart_ptr<streamCipher> strm = _streamPackage->buildStream(_password,_passwordLength);
			os::smart_ptr<unsigned char> streamArr(new unsigned char[BLOCK_SIZE*_publicKeys.size()],os::shared_type_array);
			for(unsigned int i=0;i<BLOCK_SIZE*_publicKeys.size();i++)
				streamArr[i]=strm->getNext();

			unsigned int trc=0;
			for(auto it=_publicKeys.getFirst();it;it=it->getNext())
			{
				it->getData()->setPassword(streamArr.get()+trc*BLOCK_SIZE,BLOCK_SIZE);
				trc++;
			}
		}
		else
		{
			for(auto it=_publicKeys.getFirst();it;it=it->getNext())
				it->getData()->setPassword("");
		}

		markChanged();
	}
	//Set stream package
	void user::setStreamPackage(os::smart_ptr<streamPackageFrame> strmPack)
	{
		_streamPackage=strmPack->getCopy();
		_keyBank->setStreamPackage(_streamPackage);

		markChanged();
	}
	//Sets the default public key
	bool user::setDefaultPublicKey(os::smart_ptr<publicKey> key)
	{
		if(key==NULL) return false;
		if(!_publicKeys.find(key)) return false;
		_defaultKey=key;
		if(_defaultKey) _keyBank->setPublicKey(_defaultKey);
		markChanged();
		return true;
	}
	//Adds a public key to the list
	bool user::addPublicKey(os::smart_ptr<publicKey> key)
	{
		if(!key) return false;
		if(!_publicKeys.insert(key)) return false;

		//Bind key to this
		bindSavable(os::cast<os::savable,publicKey>(key));
		key->setEncryptionAlgorithm(_streamPackage);
		key->setFileName(_saveDir+"/"+_username+"/"+key->algorithmName()+"_"+std::to_string(key->size()*32)+"_"+PUBLIC_KEY_FILE);

		//Set passwords (if appropriate)
		if(_password!=NULL && _passwordLength>0)
		{
			os::smart_ptr<streamCipher> strm = _streamPackage->buildStream(_password,_passwordLength);
			os::smart_ptr<unsigned char> streamArr(new unsigned char[BLOCK_SIZE*_publicKeys.size()],os::shared_type_array);
			for(unsigned int i=0;i<BLOCK_SIZE*_publicKeys.size();i++)
				streamArr[i]=strm->getNext();

			unsigned int trc=0;
			for(auto it=_publicKeys.getFirst();it;it=it->getNext())
			{
				it->getData()->setPassword(streamArr.get()+trc*BLOCK_SIZE,BLOCK_SIZE);
				trc++;
			}
		}

		if(!_defaultKey) setDefaultPublicKey(key);
		bindSavable(os::cast<os::savable,publicKey>(key));
		markChanged();
		return true;
	}
	//Search public key based on public-key frame
	os::smart_ptr<publicKey> user::findPublicKey(os::smart_ptr<publicKeyPackageFrame> pkfrm)
	{
		if(!pkfrm) return NULL;
		os::smart_ptr<publicKey> tpk=pkfrm->bindKeys(NULL,NULL);
		auto it=_publicKeys.find(tpk);
		if(!it) return NULL;
		return it->getData();
	}

	//Searching for key
	os::smart_ptr<publicKey> user::searchKey(hash hsh, unsigned int& hist,bool& type)
	{
		auto trc=_publicKeys.getFirst();
		while(trc)
		{
			if(trc->getData()->searchKey(hsh,hist,type))
				return trc->getData();
			trc=trc->getNext();
		}
		return NULL;
	}
	os::smart_ptr<publicKey> user::searchKey(os::smart_ptr<number> key, unsigned int& hist,bool& type)
	{
		auto trc=_publicKeys.getFirst();
		while(trc)
		{
			if(trc->getData()->searchKey(key,hist,type))
				return trc->getData();
			trc=trc->getNext();
		}
		return NULL;
	}
}

#endif

///@endcond
/**
 * @file	user.cpp
 * @author	Jonathan Bedard
 * @date   	7/13/2016
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

#include "gateway.h"
#include "user.h"

#define META_FILE "metaData.xml"
#define KEY_BANK_FILE "keyBank.xml"
#define PUBLIC_KEY_FILE "publicKey.bin"
#define GATEWAY_SETTINGS_FILE "Settings.bin"
#define BLOCK_SIZE 20

namespace crypto {
    
/*-----------------------------------
     User Constructor
  -----------------------------------*/

	//User constructor
	user::user(std::string username,std::string saveDir,const unsigned char* key,size_t keyLen)
	{
		//Basic initializers
		if(_username.size()>size::NAME_SIZE)
			throw errorPointer(new stringTooLarge(),os::shared_type);
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
					for(unsigned int i=0;i<BLOCK_SIZE*xmlList->size();++i)
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
					++trc;
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

			//Build settings (can only do this if public keys are defined
			if(_publicKeys.size()>0)
			{
				xmlList=readTree->findElement("gatewaySettings");
				if(xmlList->size()!=1)
				{
					logError(errorPointer(new fileFormatError(),os::shared_type));
					return;
				}
				os::smartXMLNode gateNode=xmlList->getFirst()->getData();
				xmlList=gateNode->findElement("node");
				for(auto it=xmlList->getFirst();it;it=it->getNext())
				{
					os::smart_ptr<gatewaySettings> gtws=insertSettings(it->getData()->getData());
					if(gtws) gtws->load();
				}
			}
		}

		//Load Key bank
		if(_defaultKey) _keyBank=os::smart_ptr<keyBank>(new avlKeyBank(_saveDir+"/"+_username+"/"+KEY_BANK_FILE,_defaultKey,_streamPackage),os::shared_type);
		else _keyBank=os::smart_ptr<keyBank>(new avlKeyBank(_saveDir+"/"+_username+"/"+KEY_BANK_FILE,_password,_passwordLength,_streamPackage),os::shared_type);

		bindSavable(_keyBank.get());
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
		lv3->setData(std::to_string((long long unsigned int)_streamPackage->hashSize()*8));
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
		else lv3->setData(std::to_string((long long unsigned int)_defaultKey->size()*32));
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
			lv4->setData(std::to_string((long long unsigned int)it->getData()->size()*32));
			lv3->addElement(lv4);
			lv2->addElement(lv3);
		}
		lv1->addElement(lv2);

		ret->addElement(lv1);

		//List of gateway settings
		lv1=os::smartXMLNode(new os::XML_Node("gatewaySettings"),os::shared_type);
		for(auto it=_settings.getFirst();it;it=it->getNext())
		{
			lv2=os::smartXMLNode(new os::XML_Node("node"),os::shared_type);
			lv2->setData(it->getData()->groupID());
			lv1->addElement(lv2);
		}
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
	void user::setPassword(const unsigned char* key,size_t keyLen)
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
			for(unsigned int i=0;i<BLOCK_SIZE*_publicKeys.size();++i)
				streamArr[i]=strm->getNext();

			unsigned int trc=0;
			for(auto it=_publicKeys.getFirst();it;it=it->getNext())
			{
				it->getData()->setPassword(streamArr.get()+trc*BLOCK_SIZE,BLOCK_SIZE);
				++trc;
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

		for(auto i=_settings.getFirst();i;i=i->getNext())
			i->getData()->update();
		if(_settings.size()==0 && _defaultKey)
		{
			insertSettings("default");
		}


		markChanged();
		return true;
	}
	//Adds a public key to the list
	bool user::addPublicKey(os::smart_ptr<publicKey> key)
	{
		if(!key) return false;
		if(!_publicKeys.insert(key)) return false;

		//Bind key to this
		bindSavable(key.get());
		key->setEncryptionAlgorithm(_streamPackage);
		key->setFileName(_saveDir+"/"+_username+"/"+key->algorithmName()+"_"+std::to_string((long long unsigned int)key->size()*32)+"_"+PUBLIC_KEY_FILE);
		key->markChanged();

		//Set passwords (if appropriate)
		if(_password!=NULL && _passwordLength>0)
		{
			os::smart_ptr<streamCipher> strm = _streamPackage->buildStream(_password,_passwordLength);
			os::smart_ptr<unsigned char> streamArr(new unsigned char[BLOCK_SIZE*_publicKeys.size()],os::shared_type_array);
			for(unsigned int i=0;i<BLOCK_SIZE*_publicKeys.size();++i)
				streamArr[i]=strm->getNext();

			unsigned int trc=0;
			for(auto it=_publicKeys.getFirst();it;it=it->getNext())
			{
				it->getData()->setPassword(streamArr.get()+trc*BLOCK_SIZE,BLOCK_SIZE);
				++trc;
			}
		}

		if(!_defaultKey) setDefaultPublicKey(key);
		bindSavable(key.get());
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

	//Find settings group
	os::smart_ptr<gatewaySettings> user::findSettings(std::string group)
	{
		os::smart_ptr<gatewaySettings> temp(new gatewaySettings(this,group,""),os::shared_type);
		auto hld=_settings.find(temp);
		if(hld) return hld->getData();
		return NULL;
	}
	//Insert settings group
	os::smart_ptr<gatewaySettings> user::insertSettings(std::string group)
	{
		os::smart_ptr<gatewaySettings> temp(new gatewaySettings(this,group,""),os::shared_type);
		auto hld=_settings.find(temp);
		if(hld) return hld->getData();

		if(_saveDir=="")
			temp = os::smart_ptr<gatewaySettings>(new gatewaySettings(this,group,""),os::shared_type);
		else
		{
			temp = os::smart_ptr<gatewaySettings>(new gatewaySettings(this,group,_saveDir+"/"+_username+"/"+group+GATEWAY_SETTINGS_FILE),os::shared_type);
			bindSavable(temp.get());
		}
		_settings.insert(temp);
		return temp;
	}
	
	//Searching for key
	os::smart_ptr<publicKey> user::searchKey(hash hsh, size_t& hist,bool& type)
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
	os::smart_ptr<publicKey> user::searchKey(os::smart_ptr<number> key, size_t& hist,bool& type)
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

/*-----------------------------------
	Raw message passing
  -----------------------------------*/

	//Unsigned ID message
	unsigned char* user::unsignedIDMessage(size_t& len, std::string groupID,std::string nodeName)
	{
		len=0;
		os::smart_ptr<nodeGroup> nd=_keyBank->find(groupID,nodeName);
		os::smart_ptr<nodeKeyReference> targKey;
		os::smart_ptr<publicKey> pbk=getDefaultPublicKey();
		os::smart_ptr<streamPackageFrame> stmpk=streamPackage();
		if(!pbk) return NULL;
		if(!stmpk) return NULL;
		if(!findSettings(groupID)) return NULL;

		//Everything needs the basic header
		len=1+size::GROUP_SIZE+size::NAME_SIZE+5+2*pbk->size()*4;
		if(nd)
		{
			auto cap=nd->getFirstKey();
			if(cap) targKey=cap->getData();
			if(targKey)
				len+=stmpk->hashSize()+targKey->keySize()*4;
		}
		
		//Build return array
		unsigned char* ret=new unsigned char[len];
		memset(ret,0,len);
		if(targKey) ret[0]=0x80;

		//Place in the group ID first
		size_t trc=1;
		memcpy(ret+trc,groupID.c_str(),groupID.length());
		trc+=size::GROUP_SIZE;

		//Bind algorithm data
		ret[trc]=(unsigned char) pbk->algorithm();
		ret[trc+1]=(unsigned char) pbk->size();
		ret[trc+2]=(unsigned char) stmpk->hashAlgorithm();
		ret[trc+3]=(unsigned char) stmpk->hashSize();
		ret[trc+4]=(unsigned char) stmpk->streamAlgorithm();
		trc+=5;

		//Prepare for encryption data (if targeted)
		os::smart_ptr<streamCipher> cipher;
		size_t cipherStart;
		size_t tempLen;
		if(targKey)
		{
			auto arr=targKey->key()->getCompCharData(tempLen);
			hash hsh=stmpk->hashData(arr.get(),tempLen);
			memcpy(ret+trc,hsh.data(),hsh.size());
			trc+=stmpk->hashSize();

			for(uint16_t i=0;i<targKey->keySize()*4;++i)
				ret[trc+i]=rand();
			ret[trc+targKey->keySize()*4-1]=rand()&0x0F;
			cipher=stmpk->buildStream(ret+trc,targKey->keySize()*4);
			trc+=targKey->keySize()*4;
			cipherStart=trc;
		}

		//Place in name
		memcpy(ret+trc,_username.c_str(),_username.length());
		trc+=size::NAME_SIZE;

		//Place in key
		auto arr=pbk->getN()->getCompCharData(tempLen);
		memcpy(ret+trc,arr.get(),tempLen);
		trc+=tempLen;

		//Hash all data
		hash hsh=stmpk->hashData(ret+1,len-1-pbk->size()*4);
		os::smart_ptr<number> num1;
		if(hsh.size()>pbk->size()*4) num1=pbk->copyConvert(hsh.data(),pbk->size()*4);
		else num1=pbk->copyConvert(hsh.data(),hsh.size());
		num1->data()[pbk->size()-1]&=(~(uint32_t)0)>>6;
		try{num1=pbk->decode(num1);}
		catch(...)
		{
			len=0;
			delete [] ret;
			return NULL;
		}
		arr=num1->getCompCharData(tempLen);
		memcpy(ret+trc,arr.get(),tempLen);

		//Now encrypt
		if(cipher && targKey)
		{
			for(size_t i=cipherStart;i<len;++i)
				ret[i]=cipher->getNext()^ret[i];

			os::smart_ptr<publicKeyPackageFrame> pkfrm=publicKeyTypeBank::singleton()->findPublicKey(targKey->algoID());
			if(!pkfrm)
			{
				len=0;
				delete [] ret;
				return NULL;
			}
			pkfrm=pkfrm->getCopy();
			pkfrm->setKeySize(targKey->keySize());
			pkfrm->encode(ret+cipherStart-targKey->keySize()*4,targKey->keySize()*4,targKey->key());
		}

		return ret;
	}
	//Process an ID message
	bool user::processIDMessage(unsigned char* mess, size_t len)
	{
		//Check message header
		if(!isIDMessage(mess[0])) return false;
		if(len < 1+size::GROUP_SIZE+size::NAME_SIZE+5) return false;
		if(!mess) return false;
		unsigned int trc=1;

		//Pull group ID
		os::smart_ptr<publicKeyPackageFrame> pbk;
		os::smart_ptr<streamPackageFrame> stmpk;
		std::string groupID;
		if(trc+size::GROUP_SIZE>=len) return false;
		char* tID=new char[size::GROUP_SIZE+1];
		memset(tID,0,size::GROUP_SIZE+1);
		memcpy(tID,mess+trc,size::GROUP_SIZE);
		groupID=std::string(tID);
		delete [] tID;
		trc+=size::GROUP_SIZE;
		if(!findSettings(groupID)) return false;

		//Pull algorithm
		if(trc+5>=len) return false;
		uint16_t pbkID=mess[trc];
		uint16_t pbkSize=mess[trc+1];
		uint16_t hshAlgo=mess[trc+2];
		uint16_t hshSize=mess[trc+3];
		uint16_t strmAlgo=mess[trc+4];

		pbk=publicKeyTypeBank::singleton()->findPublicKey(pbkID);
		stmpk=streamPackageTypeBank::singleton()->findStream(strmAlgo,hshAlgo);
		if(!pbk) return NULL;
		if(!stmpk) return NULL;
		pbk=pbk->getCopy();
		stmpk=stmpk->getCopy();
		pbk->setKeySize(pbkSize);
		stmpk->setHashSize(hshSize);
		trc+=5;

		//Check for key
		if(isEncrypted(mess[0]))
		{
			if(trc+stmpk->hashSize()>=len) return false;
			hash hsh=stmpk->hashCopy(mess+trc);
			trc+=stmpk->hashSize();

			size_t hist;
			bool type;
			os::smart_ptr<publicKey> myKey=searchKey(hsh,hist,type);
			if(!myKey) return false;
			if(trc+myKey->size()*4>=len) return false;
			myKey->decode(mess+trc,myKey->size()*4,hist);

			os::smart_ptr<streamCipher> cipher=stmpk->buildStream(mess+trc,myKey->size()*4);
			trc+=myKey->size()*4;
			for(int i=trc;i<len;++i)
				mess[i]=mess[i]^cipher->getNext();
		}

		//Pull name
		if(trc+size::NAME_SIZE>=len) return false;
		std::string nodeName;
		tID=new char[size::NAME_SIZE+1];
		memset(tID,0,size::NAME_SIZE+1);
		memcpy(tID,mess+trc,size::NAME_SIZE);
		nodeName=std::string(tID);
		delete [] tID;
		trc+=size::NAME_SIZE;

		//Process key
		if(trc+pbkSize*4>=len) return false;
		os::smart_ptr<nodeGroup> nd=_keyBank->find(groupID,nodeName);
		os::smart_ptr<number> broKey=pbk->convert(mess+trc,pbkSize*4);
		trc+=pbkSize*4;

		//Check data hash
		if(trc+pbk->keySize()*4>len) return false;
		os::smart_ptr<number> num2=pbk->convert(mess+trc,pbk->keySize()*4);
		hash hsh=stmpk->hashData(mess+1,len-1-pbk->keySize()*4);
		os::smart_ptr<number> num1;
		if(hsh.size()>pbk->keySize()*4) num1=pbk->convert(hsh.data(),pbk->keySize()*4);
		else num1=pbk->convert(hsh.data(),hsh.size());
		num1->data()[pbk->keySize()-1]&=(~(uint32_t)0)>>6;

		try{num2=pbk->encode(num2,broKey);}
		catch(...) {return false;}
		if(*num1 != *num2) return false;

		if(nd)
		{
			if(nd!=_keyBank->find(broKey,pbkID,pbkSize))
				return false;
		}
		else
			_keyBank->addPair(groupID,nodeName,broKey,pbkID,pbkSize);

		return true;
	}
	//Encrypt a message
	unsigned char* user::encryptMessage(size_t& finishedLen, const unsigned char* mess, size_t len, std::string groupID,std::string nodeName)
	{
		finishedLen=0;
		os::smart_ptr<nodeGroup> nd=_keyBank->find(groupID,nodeName);
		os::smart_ptr<nodeKeyReference> targKey;
		os::smart_ptr<streamPackageFrame> stmpk=streamPackage();
		os::smart_ptr<publicKey> pbk=getDefaultPublicKey();

		if(!nd) return NULL;
		if(!stmpk) return NULL;
		if(!pbk) return NULL;
		auto cap=nd->getFirstKey();
		if(cap) targKey=cap->getData();
		if(!targKey) return NULL;

		finishedLen=pbk->size()*4+len+6+targKey->keySize()*4;
		unsigned char* ret=new unsigned char[finishedLen];
		ret[0]=0x01|0x80;
		size_t trc=1;

		ret[trc]=(unsigned char)pbk->algorithm();
		ret[trc+1]=(unsigned char)pbk->size();
		ret[trc+2]=(unsigned char)stmpk->hashAlgorithm();
		ret[trc+3]=(unsigned char)stmpk->hashSize();
		ret[trc+4]=(unsigned char)stmpk->streamAlgorithm();
		trc+=5;

		//Prepare for encryption data (if targeted)
		os::smart_ptr<streamCipher> cipher;
		size_t cipherStart;
		size_t tempLen;

		for(int i=0;i<targKey->keySize()*4;++i)
			ret[trc+i]=rand();
		ret[trc+targKey->keySize()*4-1]=rand()&0x0F;
		cipher=stmpk->buildStream(ret+trc,targKey->keySize()*4);
		trc+=targKey->keySize()*4;
		cipherStart=trc;

		//Bind data
		memcpy(ret+trc,mess,len);
		trc+=len;

		//Hash all data
		hash hsh=stmpk->hashData(ret+1,finishedLen-1-pbk->size()*4);
		os::smart_ptr<number> num1;
		if(hsh.size()>pbk->size()*4) num1=pbk->copyConvert(hsh.data(),pbk->size()*4);
		else num1=pbk->copyConvert(hsh.data(),hsh.size());
		num1->data()[pbk->size()-1]&=(~(uint32_t)0)>>6;
		try{num1=pbk->decode(num1);}
		catch(...)
		{
			finishedLen=0;
			delete [] ret;
			return NULL;
		}
		auto arr=num1->getCompCharData(tempLen);
		memcpy(ret+trc,arr.get(),tempLen);

		//Now encrypt
		for(size_t i=cipherStart;i<finishedLen;++i)
			ret[i]=cipher->getNext()^ret[i];

		os::smart_ptr<publicKeyPackageFrame> pkfrm=publicKeyTypeBank::singleton()->findPublicKey(targKey->algoID());
		if(!pkfrm)
		{
			finishedLen=0;
			delete [] ret;
			return NULL;
		}
		pkfrm=pkfrm->getCopy();
		pkfrm->setKeySize(targKey->keySize());
		try
		{
			pkfrm->encode(ret+cipherStart-targKey->keySize()*4,targKey->keySize()*4,targKey->key());
		} catch(...)
		{
			finishedLen=0;
			delete [] ret;
			return NULL;
		}
		
		return ret;
	}
	//Decrypt a message
	unsigned char* user::decryptMessage(size_t& finishedLen, const unsigned char* mess, size_t len, std::string groupID,std::string nodeName)
	{
		//Check message header
		os::smart_ptr<publicKeyPackageFrame> pbkfrm;
		os::smart_ptr<streamPackageFrame> stmpk;
		os::smart_ptr<nodeGroup> nd=_keyBank->find(groupID,nodeName);
		os::smart_ptr<nodeKeyReference> targKey;
		os::smart_ptr<publicKey> pbk=getDefaultPublicKey();
		finishedLen=0;

		if(!isDataMessage(mess[0]) || len<=1)
			return NULL;
		if(!isEncrypted(mess[0]))
		{
			finishedLen=len-1;
			unsigned char* targ=new unsigned char[finishedLen];
			memcpy(targ,mess+1,finishedLen);
			return targ;
		}
		if(len<6) return NULL;

		size_t trc=1;
		uint16_t pbkID=mess[trc];
		uint16_t pbkSize=mess[trc+1];
		uint16_t hshAlgo=mess[trc+2];
		uint16_t hshSize=mess[trc+3];
		uint16_t strmAlgo=mess[trc+4];

		pbkfrm=publicKeyTypeBank::singleton()->findPublicKey(pbkID);
		stmpk=streamPackageTypeBank::singleton()->findStream(strmAlgo,hshAlgo);
		
		if(!pbkfrm) return NULL;
		if(!pbk) return NULL;
		if(!stmpk) return NULL;
		if(!nd) return NULL;
		auto cap=nd->getFirstKey();
		if(cap) targKey=cap->getData();
		if(!targKey) return NULL;

		pbkfrm=pbkfrm->getCopy();
		stmpk=stmpk->getCopy();
		pbkfrm->setKeySize(pbkSize);
		stmpk->setHashSize(hshSize);
		trc+=5;

		//Temp message
		if(len<pbk->size()+6+targKey->keySize()) return NULL;
		unsigned char* temp=new unsigned char[len];
		memcpy(temp,mess,len);
		try
		{
			pbk->decode(temp+trc,pbk->size()*4);
		}catch(...)
		{
			delete [] temp;
			return NULL;
		}

		//Now decrypt
		os::smart_ptr<streamCipher> cipher=stmpk->buildStream(temp+trc,targKey->keySize()*4);
		trc+=pbk->size()*4;
		for(size_t i=trc;i<len;++i)
			temp[i]=cipher->getNext()^temp[i];

		//Pull message
		if(len<(pbk->size()+6+targKey->keySize()))
		{
			delete [] temp;
			return NULL;
		}
		finishedLen=len-(pbk->size()*4+6+targKey->keySize()*4);
		unsigned char* ret=new unsigned char[finishedLen];
		memcpy(ret,temp+trc,finishedLen);
		trc+=finishedLen;

		//Check data hash
		hash hsh=stmpk->hashData(temp+1,len-1-pbkfrm->keySize()*4);
		os::smart_ptr<number> num1;
		if(hsh.size()>pbkfrm->keySize()*4) num1=pbkfrm->convert(hsh.data(),pbkfrm->keySize()*4);
		else num1=pbkfrm->convert(hsh.data(),hsh.size());
		num1->data()[pbk->size()-1]&=(~(uint32_t)0)>>6;

		os::smart_ptr<number> num2=pbkfrm->convert(temp+trc,pbkfrm->keySize()*4);
		try{num2=pbkfrm->encode(num2,targKey->key());}
		catch(...)
		{
			finishedLen=0;
			delete [] ret;
			return NULL;
		}
		if(*num1!=*num2)
		{
			finishedLen=0;
			delete [] ret;
			return NULL;
		}

		return ret;
	}

}

#endif

///@endcond
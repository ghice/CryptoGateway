//Primary author: Jonathan Bedard
//Confirmed working: 1/17/2016

#ifndef CRYPTO_PUBLIC_KEY_CPP
#define CRYPTO_PUBLIC_KEY_CPP

#include "cryptoPublicKey.h"
#include "cryptoError.h"
#include "binaryEncryption.h"

using namespace crypto;

/*------------------------------------------------------------
     Public Key Frame
 ------------------------------------------------------------*/

	//Public key constructor (with size and algorithm)
	publicKey::publicKey(uint16_t sz)
	{
		_size=sz;

		_key=NULL;
		_keyLen=0;
		_fileName="";
	}
	//Public key constructor
	publicKey::publicKey(os::smart_ptr<number> _n,os::smart_ptr<number> _d,uint16_t sz)
	{
		if(!_n || !_d) throw errorPointer(new customError("NULL Keys","Attempted to bind NULL keys to a public key frame"),os::shared_type);
		if(_n->size()!=sz || _d->size()!=sz) throw errorPointer(new customError("Key Size Error","Attempted to bind keys of wrong size"),os::shared_type);
		_size=sz;
		
		_n=copyConvert(_n);
		_d=copyConvert(_d);
		_key=NULL;
		_keyLen=0;
		_fileName="";
	}
	//Password constructor
	publicKey::publicKey(std::string fileName,std::string password,os::smart_ptr<streamPackageFrame> stream_algo)
	{
		if(fileName=="") throw errorPointer(new fileOpenError(),os::shared_type);
		_size=0;
		_fileName=fileName;

		_key=NULL;
		_keyLen=0;

		setPassword(password);
		setEncryptionAlgorithm(stream_algo);
	}
	//Password constructor
	publicKey::publicKey(std::string fileName,unsigned char* key,unsigned int keyLen,os::smart_ptr<streamPackageFrame> stream_algo)
	{
		if(fileName=="") throw errorPointer(new fileOpenError(),os::shared_type);
		_size=0;
		_fileName=fileName;

		_key=NULL;
		_keyLen=0;

		setPassword(key,keyLen);
		setEncryptionAlgorithm(stream_algo);
	}
	//Destructor
	publicKey::~publicKey()
	{
		if(_key) delete [] _key;
	}

	//Copy convert
	os::smart_ptr<number> publicKey::copyConvert(const os::smart_ptr<number> num) const
	{
		os::smart_ptr<number> ret(new number(*num),os::shared_type);
		ret->expand(_size*2);
		return ret;
	}
	//Copy convert
	os::smart_ptr<number> publicKey::copyConvert(const uint32_t* arr,uint16_t len) const
	{
		os::smart_ptr<number> ret(new number(arr,len),os::shared_type);
		ret->expand(_size*2);
		return ret;
	}

//Access and Generation----------------------------------------

	//Return 'N'
	os::smart_ptr<number> publicKey::getN() const
	{
		if(!n) return NULL;
		return copyConvert(n);
	}
	//Return the old N
	os::smart_ptr<number> publicKey::getOldN(unsigned int history)
	{
		if(history>=oldN.size()) return NULL;

		oldN.resetTraverse();
		auto trc=oldN.getFirst();
		for(unsigned int i=0;i<history&&trc;i++)
		{
			trc=trc->getNext();
		}
		if(!trc) return NULL;
		return trc->getData();
	}
	//Generate a new key
	void publicKey::generateNewKeys()
	{
		if(n && d)
		{
			oldN.insert(n);
			oldD.insert(d);
		}
		n=os::smart_ptr<number>(new number(),os::shared_type);
		d=os::smart_ptr<number>(new number(),os::shared_type);

		n->expand(2*_size);
		d->expand(2*_size);
	}

//File loading and saving-------------------------------------

	//Save file
	void publicKey::saveFile() const
	{
		if(_fileName=="") throw errorPointer(new fileOpenError(),os::shared_type);

		//No encryption
		os::smart_ptr<binaryEncryptor> ben;
		if(_key==NULL || _keyLen==0) ben=os::smart_ptr<binaryEncryptor>(new binaryEncryptor(_fileName,"default"),os::shared_type);
		else ben=os::smart_ptr<binaryEncryptor>(new binaryEncryptor(_fileName,_key,_keyLen,fePackage),os::shared_type);

		os::smart_ptr<unsigned char>dumpArray(new unsigned char[2*4*_size],os::shared_type_array);
		uint16_t dumpVal;

		//Write size and algorithm
		dumpVal=os::to_comp_mode(_size);
		memcpy(dumpArray.get(),&dumpVal,2);
		dumpVal=os::to_comp_mode(algorithm());
		memcpy(dumpArray.get()+2,&dumpVal,2);
		ben->write(dumpArray.get(),4);

		//Write keys
		for(unsigned int i1=0;i1<2;i1++)
		{
			os::smart_ptr<number> t;
			if(i1==0) t=n;
			else t=d;
			for(unsigned int i2=0;i2<_size;i2++)
			{
				dumpVal=os::to_comp_mode(t->data()[i2]);
				memcpy(dumpArray.get()+i1*4*_size+i2*4,&dumpVal,4);
			}
		}
		ben->write(dumpArray.get(),2*4*_size);

		//If the write failed, throw flag
		if(!ben->good()) throw errorPointer(new actionOnFileError(),os::shared_type);

	}
	//Set the file name
	void publicKey::setFileName(std::string fileName){_fileName=fileName;}
	//Set password (by array)
	void publicKey::setPassword(unsigned char* key,unsigned int keyLen)
	{
		if(_key) delete [] _key;
		_key=NULL;
		if(!key || keyLen==0) return;

		_keyLen=keyLen;
		_key=new unsigned char[_keyLen];
		memcpy(_key,key,_keyLen);
	}
	//Set password (by string)
	void publicKey::setPassword(std::string password)
	{
		if(password=="") setPassword(NULL,0);
		else setPassword((unsigned char*)password.c_str(),password.length());
	}
	//Set algorithm to be used in encryption
	void publicKey::setEncryptionAlgorithm(os::smart_ptr<streamPackageFrame> stream_algo) {fePackage=stream_algo;}

#endif
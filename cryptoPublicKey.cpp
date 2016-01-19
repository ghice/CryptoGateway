//Primary author: Jonathan Bedard
//Confirmed working: 1/19/2016

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
    //Copy public key
    publicKey::publicKey(const publicKey& ky)
    {
        _size=ky._size;
        _fileName="";
        
        //Copy encryption key
        if(ky._key==NULL)
        {
            _key=NULL;
            _keyLen=NULL;
        }
        else
        {
            _key=new unsigned char[ky._keyLen];
            _keyLen=ky._keyLen;
            memcpy(_key,ky._key,_keyLen);
        }
    }
    //Public key constructor
	publicKey::publicKey(os::smart_ptr<number> _n,os::smart_ptr<number> _d,uint16_t sz)
	{
		if(!_n || !_d) throw errorPointer(new customError("NULL Keys","Attempted to bind NULL keys to a public key frame"),os::shared_type);
		if(_n->size()!=sz || _d->size()!=sz) throw errorPointer(new customError("Key Size Error","Attempted to bind keys of wrong size"),os::shared_type);
		_size=sz;
		
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

		//Fine encryption type
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
    //Opens a key file
    void publicKey::loadFile()
    {
        if(_fileName=="") throw errorPointer(new fileOpenError(),os::shared_type);
        
        os::smart_ptr<binaryDecryptor> bde;
        if(_key==NULL || _keyLen==0) bde=os::smart_ptr<binaryDecryptor>(new binaryDecryptor(_fileName,"default"),os::shared_type);
        else bde=os::smart_ptr<binaryDecryptor>(new binaryDecryptor(_fileName,_key,_keyLen),os::shared_type);
        
        //Check if this is even a good file
        if(!bde->good()) throw errorPointer(new actionOnFileError(),os::shared_type);
        
        //Read in header
        unsigned char initArray[4];
        uint16_t dumpVal;
        bde->read(initArray,4);
        if(!bde->good()) throw errorPointer(new actionOnFileError(),os::shared_type);
        memcpy(&dumpVal,initArray,2);
        _size=os::from_comp_mode(dumpVal);
        memcpy(&dumpVal,initArray+2,2);
        if(algorithm()!=os::from_comp_mode(dumpVal)) throw errorPointer(new illegalAlgorithmBind("RSA File Read"),os::shared_type);
        
        //Read keys
        os::smart_ptr<unsigned char>dumpArray(new unsigned char[2*4*_size],os::shared_type_array);
        bde->read(initArray,4);
        if(!bde->good()) throw errorPointer(new actionOnFileError(),os::shared_type);
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

/*------------------------------------------------------------
    RSA Public Key
 ------------------------------------------------------------*/

    //Default constructor
    publicRSA::publicRSA(uint16_t sz):
        publicKey(sz)
    {
        initE();
        generateNewKeys();
    }
    //Copy constructor
    publicRSA::publicRSA(publicRSA& ky):
        publicKey(ky)
    {
        initE();
        n=copyConvert(ky.n);
        d=copyConvert(ky.d);
        
        //Copy old n
        ky.oldN.resetTraverse();
        for(auto trc=ky.oldN.getLast();trc;trc=trc->getPrev())
            oldN.insert(trc->getData());
        
        //Copy old d
        ky.oldD.resetTraverse();
        for(auto trc=ky.oldD.getLast();trc;trc=trc->getPrev())
            oldD.insert(trc->getData());
    }
    //N, D constructor
    publicRSA::publicRSA(os::smart_ptr<integer> _n,os::smart_ptr<integer> _d,uint16_t sz):
        publicKey(os::cast<number,integer>(_n),os::cast<number,integer>(_d),sz)
    {
        initE();
        n=copyConvert(os::cast<number,integer>(_n));
        d=copyConvert(os::cast<number,integer>(_d));
    }
    //Load a public key from a file
    publicRSA::publicRSA(std::string fileName,std::string password,os::smart_ptr<streamPackageFrame> stream_algo):
        publicKey(fileName,password,stream_algo)
    {
        initE();
        loadFile();
    }
    //Load a public key from a file
    publicRSA::publicRSA(std::string fileName,unsigned char* key,unsigned int keyLen,os::smart_ptr<streamPackageFrame> stream_algo):
        publicKey(fileName,key,keyLen,stream_algo)
    {
        initE();
        loadFile();
    }
    //Init the "e" variable
    void publicRSA::initE()
    {
        integer one(1);
        e=(one<<16)+one;
    }
    //Copy a number and return it
    os::smart_ptr<number> publicRSA::copyConvert(const os::smart_ptr<number> num) const
    {
        os::smart_ptr<number> ret(new integer(num->data(),num->size()),os::shared_type);
        ret->expand(size()*2);
        return ret;
    }
    //Copy a raw data array and return it
    os::smart_ptr<number> publicRSA::copyConvert(const uint32_t* arr,uint16_t len) const
    {
        os::smart_ptr<number> ret(new integer(arr,len),os::shared_type);
        ret->expand(size()*2);
        return ret;
    }

#endif
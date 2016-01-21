//Primary author: Jonathan Bedard
//Confirmed working: 1/21/2016

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
        _history=10;

		_key=NULL;
		_keyLen=0;
		_fileName="";
	}
    //Copy public key
    publicKey::publicKey(const publicKey& ky)
    {
        _size=ky._size;
        _history=10;
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
		_history=10;
        
		_key=NULL;
		_keyLen=0;
		_fileName="";
	}
	//Password constructor
	publicKey::publicKey(std::string fileName,std::string password,os::smart_ptr<streamPackageFrame> stream_algo)
	{
		if(fileName=="") throw errorPointer(new fileOpenError(),os::shared_type);
		_size=0;
        _history=10;
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
        _history=10;
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
	//Copy convert for raw byte array
	os::smart_ptr<number> publicKey::copyConvert(const unsigned char* arr,unsigned int len) const
	{
		uint32_t* dumpArray=new uint32_t[len/4+1];
		memset(dumpArray,0,4*(len/4+1));
		memcpy(dumpArray,arr,len);
		os::smart_ptr<number> ret=copyConvert(dumpArray,len/4+1);
		delete [] dumpArray;
		return ret;
	}
	//Compare two public keys
	int publicKey::compare(const publicKey& cmp) const
	{
		//Weird NULL cases
		if(!n&&cmp.n) return -1;
		if(n&&!cmp.n) return 1;

		//N Cases
		if(n!=cmp.n)
		{
			int v=n->compare(cmp.n.get());
			if(v>0) return 1;
			else if(v<0) return -1;
		}

		//Weird NULL cases
		if(!d&&cmp.d) return -1;
		if(d&&!cmp.d) return 1;

		//D Cases
		if(d!=cmp.d)
		{
			int v=d->compare(cmp.d.get());
			if(v>0) return 1;
			else if(v<0) return -1;
		}
		return 0;
	}

//History Management-------------------------------------------

    //Push the old keys
    void publicKey::pushOldKeys(os::smart_ptr<number> n, os::smart_ptr<number> d)
    {
        if(!n || !d) return;
        if(_history==0) return;
        oldN.insert(n);
        oldD.insert(d);
        
        //Remove extra n and d
        while(oldN.size()>_history)
            oldN.findDelete(oldN.getLast()->getData());
        while(oldD.size()>_history)
            oldD.findDelete(oldN.getLast()->getData());
    }
    //Set the history length
    void publicKey::setHistory(uint16_t hist)
    {
        if(hist>20) return; //Can't keep track of more than 20 at a time
        if(hist<_history)
        {
            //Remove extra n and d
            while(oldN.size()>hist)
                oldN.findDelete(oldN.getLast()->getData());
            while(oldD.size()>hist)
                oldD.findDelete(oldN.getLast()->getData());
            
        }
        _history=hist;
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

		readLock();
		oldN.resetTraverse();
		auto trc=oldN.getFirst();
		for(unsigned int i=0;i<history&&trc;i++)
		{
			trc=trc->getNext();
		}
		readUnlock();

		if(!trc) return NULL;
		return trc->getData();
	}
	//Generate a new key
	void publicKey::generateNewKeys()
	{
		writeLock();
		if(n && d) pushOldKeys(n,d);

		n=os::smart_ptr<number>(new number(),os::shared_type);
		d=os::smart_ptr<number>(new number(),os::shared_type);

		n->expand(2*_size);
		d->expand(2*_size);
		writeUnlock();
	}

//File loading and saving-------------------------------------

	//Save file
	void publicKey::saveFile()
	{
        readLock();
		if(_fileName=="")
        {
            readUnlock();
            throw errorPointer(new fileOpenError(),os::shared_type);
        }

		//Fine encryption type
		os::smart_ptr<binaryEncryptor> ben;

		if(_key==NULL || _keyLen==0) ben=os::smart_ptr<binaryEncryptor>(new binaryEncryptor(_fileName,"default"),os::shared_type);
		else ben=os::smart_ptr<binaryEncryptor>(new binaryEncryptor(_fileName,_key,_keyLen,fePackage),os::shared_type);

		//If the write failed, throw flag
        if(!ben->good())
        {
            readUnlock();
            throw errorPointer(new actionOnFileError(),os::shared_type);
        }

		os::smart_ptr<unsigned char>dumpArray(new unsigned char[2*4*_size],os::shared_type_array);
		uint16_t dumpVal;

		//Write size and algorithm
		dumpVal=os::to_comp_mode(_size);
		memcpy(dumpArray.get(),&dumpVal,2);
		dumpVal=os::to_comp_mode(algorithm());
		memcpy(dumpArray.get()+2,&dumpVal,2);
		ben->write(dumpArray.get(),4);

		//Write keys
		uint32_t ldval;
		for(unsigned int i1=0;i1<2;i1++)
		{
			os::smart_ptr<number> t;
			if(i1==0) t=n;
			else t=d;
			for(unsigned int i2=0;i2<_size;i2++)
			{
				ldval=os::to_comp_mode(t->data()[i2]);
				memcpy(dumpArray.get()+i1*4*_size+i2*4,&ldval,4);
			}
		}
		ben->write(dumpArray.get(),2*4*_size);

		//If the write failed, throw flag
		if(!ben->good())
        {
            readUnlock();
            throw errorPointer(new actionOnFileError(),os::shared_type);
        }

        //Old n and d's
        dumpVal=os::to_comp_mode(_history);
        memcpy(dumpArray.get(),&dumpVal,2);
        ben->write(dumpArray.get(),2);
        if(!ben->good())
        {
            readUnlock();
            throw errorPointer(new actionOnFileError(),os::shared_type);
        }
        
        oldN.resetTraverse();
        oldD.resetTraverse();
        
        auto ntrc=oldN.getLast();
        auto dtrc=oldD.getLast();
        while(ntrc && dtrc)
        {
            for(unsigned int i1=0;i1<2;i1++)
            {
                os::smart_ptr<number> t;
                if(i1==0) t=ntrc->getData();
                else t=dtrc->getData();
                for(unsigned int i2=0;i2<_size;i2++)
                {
                    ldval=os::to_comp_mode(t->data()[i2]);
                    memcpy(dumpArray.get()+i1*4*_size+i2*4,&ldval,4);
                }
            }
            ben->write(dumpArray.get(),2*4*_size);
            
            //Go to the next n and d
            if(!ben->good())
            {
                readUnlock();
                throw errorPointer(new actionOnFileError(),os::shared_type);
            }
            ntrc=ntrc->getPrev();
            dtrc=dtrc->getPrev();
        }
        readUnlock();
	}
    //Opens a key file
    void publicKey::loadFile()
    {
		writeLock();
        if(_fileName=="")
		{
			writeUnlock();
			throw errorPointer(new fileOpenError(),os::shared_type);
		}
        
        os::smart_ptr<binaryDecryptor> bde;
        if(_key==NULL || _keyLen==0) bde=os::smart_ptr<binaryDecryptor>(new binaryDecryptor(_fileName,"default"),os::shared_type);
        else bde=os::smart_ptr<binaryDecryptor>(new binaryDecryptor(_fileName,_key,_keyLen),os::shared_type);
        
        //Check if this is even a good file
        if(!bde->good())
		{
			writeUnlock();
			throw errorPointer(new actionOnFileError(),os::shared_type);
		}
        
        //Read in header
        unsigned char initArray[4];
        uint16_t dumpVal;
        bde->read(initArray,4);
        if(!bde->good())
		{
			writeUnlock();
			throw errorPointer(new actionOnFileError(),os::shared_type);
		}
        memcpy(&dumpVal,initArray,2);
        _size=os::from_comp_mode(dumpVal);
        memcpy(&dumpVal,initArray+2,2);
        if(algorithm()!=os::from_comp_mode(dumpVal))
		{
			writeUnlock();
			throw errorPointer(new illegalAlgorithmBind("RSA File Read"),os::shared_type);
		}
        
        //Read keys
        os::smart_ptr<unsigned char>dumpArray(new unsigned char[2*4*_size],os::shared_type_array);
		os::smart_ptr<uint32_t>keyArray(new uint32_t[_size],os::shared_type_array);
        bde->read(dumpArray.get(),2*4*_size);
        if(!bde->good())
		{
			writeUnlock();
			throw errorPointer(new actionOnFileError(),os::shared_type);
		}

		//Parse keys
		uint32_t ldval;
		for(unsigned int i1=0;i1<2;i1++)
		{
			memcpy(keyArray.get(),dumpArray.get()+i1*4*_size,4*_size);
			for(unsigned int i2=0;i2<_size;i2++)
			{
				keyArray.get()[i2]=os::from_comp_mode(keyArray.get()[i2]);
			}
			if(i1==0) n=copyConvert(keyArray.get(),_size);
			else d=copyConvert(keyArray.get(),_size);
		}
        
        //Old n and d's
        bde->read(initArray,2);
        if(!bde->good())
        {
            writeUnlock();
            throw errorPointer(new actionOnFileError(),os::shared_type);
        }
        memcpy(&dumpVal,initArray,2);
        _history=os::from_comp_mode(dumpVal);
        if(_history>20)
        {
            writeUnlock();
            throw errorPointer(new customError("History Size","History size invalid, must be less than or equal to 20"),os::shared_type);
        }
        
		writeUnlock();
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

//Encoding and decoding---------------------------------------

	//Default encode
	os::smart_ptr<number> publicKey::encode(os::smart_ptr<number> code, os::smart_ptr<number> publicN) const
	{
		if(!publicN) publicN=n;
		if(code>publicN) throw errorPointer(new publicKeySizeWrong(), os::shared_type);
		return code;
	}
	//Encode with raw data, public key
	void publicKey::encode(unsigned char* code, unsigned int codeLength, os::smart_ptr<number> publicN) const
	{
		os::smart_ptr<number> enc=encode(copyConvert(code,codeLength),publicN);
		memcpy(code,enc->data(),codeLength);
	}
	//Encode with raw data
	void publicKey::encode(unsigned char* code, unsigned int codeLength, unsigned const char* publicN, unsigned int nLength) const{encode(code,codeLength,copyConvert(publicN,nLength));}
	//Default decode
	os::smart_ptr<number> publicKey::decode(os::smart_ptr<number> code) const
	{
		if(code>n) throw errorPointer(new publicKeySizeWrong(), os::shared_type);
		return code;
	}
	//Decode with raw data
	void publicKey::decode(unsigned char* code, unsigned int codeLength) const
	{
		os::smart_ptr<number> enc=decode(copyConvert(code,codeLength));
		memcpy(code,enc->data(),codeLength);
	}

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
        e=(integer::one()<<16)+integer::one();
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

/*------------------------------------------------------------
    RSA Public Key Generation
 ------------------------------------------------------------*/

	//Requires generating primes twice
	namespace crypto
	{
		//Key generation helper class
		class RSAKeyGenerator
		{
			publicRSA* master;
		public:
			integer p;
			integer q;

			//Basic constructor
			RSAKeyGenerator(publicRSA& m)
			{
				master=&m;
			}
			//Generate prime
			integer generatePrime()
			{
				integer ret(2*master->size());
				for(unsigned int i=0;i<master->size()/2;i++)
					ret[i]=((uint32_t) rand())^(((uint32_t)rand())<<16);
				ret[0]=ret[0]|1;
				ret[master->size()/2-1]^=1<<31;
				while(!ret.prime())
					ret+=integer::two();
				return ret;
			}
			//Push calculated values
			void pushValues()
			{
				master->writeLock();
				if(master->n && master->d) master->pushOldKeys(master->n,master->d);

				integer tn=p*q;
				integer phi = (p-integer::one())*(q-integer::one());
				phi.expand(2*master->size());
				integer td = master->e.modInverse(phi);

				master->n=os::smart_ptr<number>(new integer(tn),os::shared_type);
				master->d=os::smart_ptr<number>(new integer(td),os::shared_type);
				master->n->expand(2*master->size());
				master->d->expand(2*master->size());
                
                publicRSA* temp=master;
                temp->keyGen=NULL;
				temp->writeUnlock();
			}
		};
		//Basic key generation thread
		void generateKeys(void* ptr,os::smart_ptr<os::threadHolder> th)
		{
			RSAKeyGenerator* rkg=(RSAKeyGenerator*) ptr;
			rkg->p=rkg->generatePrime();
			rkg->q=rkg->generatePrime();
			rkg->pushValues();
		}
	}

	//Generating keys
	void publicRSA::generateNewKeys()
	{
		writeLock();

		if(keyGen)
		{
			writeUnlock();
			return;
		}

        srand(time(NULL));
		keyGen=os::smart_ptr<RSAKeyGenerator>(new RSAKeyGenerator(*this),os::shared_type);
		os::spawnThread(&generateKeys,keyGen.get(),"RSA Key Generation");
		writeUnlock();
	}
    //Checks to see if we are even generating
    bool publicRSA::generating()
    {
        writeLock();
        if(keyGen)
        {
            writeUnlock();
            return true;
        }
        writeUnlock();
        return false;
    }

#endif
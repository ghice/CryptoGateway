//Primary author: Jonathan Bedard
//Confirmed working: 1/21/2016

#ifndef CRYPTO_PUBLIC_KEY_H
#define CRYPTO_PUBLIC_KEY_H

#include "Datastructures.h"
#include "cryptoNumber.h"
#include "streamPackage.h"
#include "osMechanics.h"

namespace crypto
{
	//A public key class, base for all public key algorithms
	class publicKey
	{
		uint16_t _size;

		//File Encryption
		unsigned char* _key;
		unsigned int _keyLen;
		os::smart_ptr<streamPackageFrame> fePackage;
		std::string _fileName;
		os::multiLock keyLock;
	protected:
        os::smart_ptr<number> n;
        os::smart_ptr<number> d;
        
        os::unsortedList<number> oldN;
        os::unsortedList<number> oldD;
        
		virtual os::smart_ptr<number> copyConvert(const os::smart_ptr<number> num) const;
		virtual os::smart_ptr<number> copyConvert(const uint32_t* arr,uint16_t len) const;
		os::smart_ptr<number> copyConvert(const unsigned char* arr,unsigned int len) const;

		publicKey(uint16_t sz=size::public512);
        publicKey(const publicKey& ky);
		publicKey(os::smart_ptr<number> _n,os::smart_ptr<number> _d,uint16_t sz=size::public512);
		publicKey(std::string fileName,std::string password="",os::smart_ptr<streamPackageFrame> stream_algo=NULL);
		publicKey(std::string fileName,unsigned char* key,unsigned int keyLen,os::smart_ptr<streamPackageFrame> stream_algo=NULL);
    
		inline void writeLock() {keyLock.lock();}
		inline void writeUnlock() {keyLock.unlock();}

		int compare(const publicKey& cmp) const;
    public:
		virtual ~publicKey();

		os::smart_ptr<number> getN() const;
		os::smart_ptr<number> getOldN(unsigned int history=0);
		virtual void generateNewKeys();
		virtual uint16_t algorithm() const {return algo::publicNULL;}
        uint16_t size() const {return _size;}

		inline void readLock() {keyLock.increment();}
		inline void readUnlock() {keyLock.decrement();}

		//File loading and saving
		void saveFile() const;
        void loadFile();
		void setFileName(std::string fileName);
		void setPassword(unsigned char* key,unsigned int keyLen);
		void setPassword(std::string password);
		void setEncryptionAlgorithm(os::smart_ptr<streamPackageFrame> stream_algo);
		const std::string& fileName() const {return _fileName;}

		//Encoding and decoding
		virtual os::smart_ptr<number> encode(os::smart_ptr<number> code, os::smart_ptr<number> publicN=NULL) const;
		void encode(unsigned char* code, unsigned int codeLength, os::smart_ptr<number> publicN=NULL) const;
		void encode(unsigned char* code, unsigned int codeLength, unsigned const char* publicN, unsigned int nLength) const;
		virtual os::smart_ptr<number> decode(os::smart_ptr<number> code) const;
		void decode(unsigned char* code, unsigned int codeLength) const;

		bool operator==(const publicKey& cmp) const {return 0==compare(cmp);}
		bool operator!=(const publicKey& cmp) const {return 0!=compare(cmp);}
		bool operator<(const publicKey& cmp) const {return -1==compare(cmp);}
		bool operator>(const publicKey& cmp) const {return 1==compare(cmp);}
		bool operator<=(const publicKey& cmp) const {return 1!=compare(cmp);}
		bool operator>=(const publicKey& cmp) const {return -1!=compare(cmp);}
	};
    
    //RSA
    class publicRSA: public publicKey
    {
		friend class RSAKeyGenerator;
        integer e;
		os::smart_ptr<RSAKeyGenerator> keyGen;
        void initE();
    protected:
        os::smart_ptr<number> copyConvert(const os::smart_ptr<number> num) const;
        os::smart_ptr<number> copyConvert(const uint32_t* arr,uint16_t len) const;
    public:
        publicRSA(uint16_t sz=size::public512);
        publicRSA(publicRSA& ky);
        publicRSA(os::smart_ptr<integer> _n,os::smart_ptr<integer> _d,uint16_t sz=size::public512);
        publicRSA(std::string fileName,std::string password="",os::smart_ptr<streamPackageFrame> stream_algo=NULL);
        publicRSA(std::string fileName,unsigned char* key,unsigned int keyLen,os::smart_ptr<streamPackageFrame> stream_algo=NULL);
        
        virtual ~publicRSA(){}
        
        uint16_t algorithm() const {return algo::publicRSA;}
		void generateNewKeys();
    };
};

#endif
//Primary author: Jonathan Bedard
//Confirmed working: 1/17/2016

#ifndef CRYPTO_PUBLIC_KEY_H
#define CRYPTO_PUBLIC_KEY_H

#include "Datastructures.h"
#include "cryptoNumber.h"
#include "streamPackage.h"

namespace crypto
{
	//A public key class, base for all public key algorithms
	class publicKey
	{
		uint16_t _size;

		os::smart_ptr<number> n;
		os::smart_ptr<number> d;

		os::unsortedList<number> oldN;
		os::unsortedList<number> oldD;

		//File Encryption
		unsigned char* _key;
		unsigned int _keyLen;
		os::smart_ptr<streamPackageFrame> fePackage;
		std::string _fileName;
	protected:
		virtual os::smart_ptr<number> copyConvert(const os::smart_ptr<number> num) const;
		virtual os::smart_ptr<number> copyConvert(const uint32_t* arr,uint16_t len) const;
	public:
		publicKey(uint16_t sz=size::public512);
		publicKey(os::smart_ptr<number> _n,os::smart_ptr<number> _d,uint16_t sz=size::public512);
		publicKey(std::string fileName,std::string password="",os::smart_ptr<streamPackageFrame> stream_algo=NULL);
		publicKey(std::string fileName,unsigned char* key=NULL,unsigned int keyLen=0,os::smart_ptr<streamPackageFrame> stream_algo=NULL);
		virtual ~publicKey();

		os::smart_ptr<number> getN() const;
		os::smart_ptr<number> getOldN(unsigned int history=0);
		virtual void generateNewKeys();
		virtual uint16_t algorithm() const {return algo::streamNULL;}

		//File loading and saving
		void saveFile() const;
		void setFileName(std::string fileName);
		void setPassword(unsigned char* key,unsigned int keyLen);
		void setPassword(std::string password);
		void setEncryptionAlgorithm(os::smart_ptr<streamPackageFrame> stream_algo);
		const std::string& fileName() const {return _fileName;}
	};
};

#endif
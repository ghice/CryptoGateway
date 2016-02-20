/**
 * @file   cryptoPublicKey.h
 * @author Jonathan Bedard
 * @date   2/19/2016
 * @brief  Generalized and RSA public keys
 * @bug No known bugs.
 *
 * Contains declarations of the generalized
 * public key and the RSA public key.  These
 * classes can both encrypt and decrypt
 * public keys.
 *
 */

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
        uint16_t _history;

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

		publicKey(uint16_t sz=size::public512);
        publicKey(const publicKey& ky);
		publicKey(os::smart_ptr<number> _n,os::smart_ptr<number> _d,uint16_t sz=size::public512);
		publicKey(std::string fileName,std::string password="",os::smart_ptr<streamPackageFrame> stream_algo=NULL);
		publicKey(std::string fileName,unsigned char* key,unsigned int keyLen,os::smart_ptr<streamPackageFrame> stream_algo=NULL);
    
		inline void writeLock() {keyLock.lock();}
		inline void writeUnlock() {keyLock.unlock();}

		int compare(const publicKey& cmp) const;
        
        void pushOldKeys(os::smart_ptr<number> n, os::smart_ptr<number> d);
    public:
		virtual ~publicKey();

		virtual os::smart_ptr<number> copyConvert(const os::smart_ptr<number> num) const;
        virtual os::smart_ptr<number> copyConvert(const uint32_t* arr,uint16_t len) const;
        virtual os::smart_ptr<number> copyConvert(const unsigned char* arr,unsigned int len) const;
        
		static os::smart_ptr<number> copyConvert(const os::smart_ptr<number> num,uint16_t size);
		static os::smart_ptr<number> copyConvert(const uint32_t* arr,uint16_t len,uint16_t size);
		static os::smart_ptr<number> copyConvert(const unsigned char* arr,unsigned int len,uint16_t size);

		os::smart_ptr<number> getN() const;
		os::smart_ptr<number> getD() const;
		os::smart_ptr<number> getOldN(unsigned int history=0);
		virtual void generateNewKeys();
        virtual bool generating() {return false;}
		inline static uint16_t staticAlgorithm() {return algo::publicNULL;}
        inline static std::string staticAlgorithmName() {return "NULL Public Key";}
		inline virtual uint16_t algorithm() const {return publicKey::staticAlgorithm();}
		inline virtual std::string algorithmName() const {return publicKey::staticAlgorithmName();}
        uint16_t size() const {return _size;}

		inline void readLock() {keyLock.increment();}
		inline void readUnlock() {keyLock.decrement();}
        
        //History
        void setHistory(uint16_t hist);
        inline uint16_t history() const {return _history;}

		//File loading and saving
		void saveFile();
        void loadFile();
		void setFileName(std::string fileName);
		void setPassword(unsigned char* key,unsigned int keyLen);
		void setPassword(std::string password);
		void setEncryptionAlgorithm(os::smart_ptr<streamPackageFrame> stream_algo);
		const std::string& fileName() const {return _fileName;}

		//Encoding and decoding
        static os::smart_ptr<number> encode(os::smart_ptr<number> code, os::smart_ptr<number> publicN, uint16_t size);
        static void encode(unsigned char* code, unsigned int codeLength, unsigned const char* publicN, unsigned int nLength, uint16_t size);
        
		virtual os::smart_ptr<number> encode(os::smart_ptr<number> code, os::smart_ptr<number> publicN=NULL) const;
		void encode(unsigned char* code, unsigned int codeLength, os::smart_ptr<number> publicN=NULL) const;
		virtual void encode(unsigned char* code, unsigned int codeLength, unsigned const char* publicN, unsigned int nLength) const;
		virtual os::smart_ptr<number> decode(os::smart_ptr<number> code) const;
        void decode(unsigned char* code, unsigned int codeLength) const;

		bool operator==(const publicKey& cmp) const {return 0==compare(cmp);}
		bool operator!=(const publicKey& cmp) const {return 0!=compare(cmp);}
		bool operator<(const publicKey& cmp) const {return -1==compare(cmp);}
		bool operator>(const publicKey& cmp) const {return 1==compare(cmp);}
		bool operator<=(const publicKey& cmp) const {return 1!=compare(cmp);}
		bool operator>=(const publicKey& cmp) const {return -1!=compare(cmp);}
	};
    
	class RSAKeyGenerator;
	class publicRSA: public publicKey
	{
		friend class RSAKeyGenerator;
		integer e;
		os::smart_ptr<RSAKeyGenerator> keyGen;
		void initE();
	public:
	    publicRSA(uint16_t sz=size::public512);
	    publicRSA(publicRSA& ky);
	    publicRSA(os::smart_ptr<integer> _n,os::smart_ptr<integer> _d,uint16_t sz=size::public512);
		    publicRSA(uint32_t* _n,uint32_t* _d,uint16_t sz=size::public512);
	    publicRSA(std::string fileName,std::string password="",os::smart_ptr<streamPackageFrame> stream_algo=NULL);
	    publicRSA(std::string fileName,unsigned char* key,unsigned int keyLen,os::smart_ptr<streamPackageFrame> stream_algo=NULL);
	    
	    virtual ~publicRSA(){}

		    os::smart_ptr<number> copyConvert(const os::smart_ptr<number> num) const;
	    os::smart_ptr<number> copyConvert(const uint32_t* arr,uint16_t len) const;
	    os::smart_ptr<number> copyConvert(const unsigned char* arr,unsigned int len) const;
	    
	    static os::smart_ptr<number> copyConvert(const os::smart_ptr<number> num,uint16_t size);
	    static os::smart_ptr<number> copyConvert(const uint32_t* arr,uint16_t len,uint16_t size);
	    static os::smart_ptr<number> copyConvert(const unsigned char* arr,unsigned int len,uint16_t size);
	    
		    inline static uint16_t staticAlgorithm() {return algo::publicRSA;}
	    inline static std::string staticAlgorithmName() {return "RSA";}
	    inline uint16_t algorithm() const {return publicRSA::staticAlgorithm();}
		    inline std::string algorithmName() const {return publicRSA::staticAlgorithmName();}
	    bool generating();
		    void generateNewKeys();
	    
	    //Encoding/Decoding
	    static os::smart_ptr<number> encode(os::smart_ptr<number> code, os::smart_ptr<number> publicN, uint16_t size);
	    static void encode(unsigned char* code, unsigned int codeLength, unsigned const char* publicN, unsigned int nLength, uint16_t size);
	    
	    os::smart_ptr<number> encode(os::smart_ptr<number> code, os::smart_ptr<number> publicN=NULL) const;
	    void encode(unsigned char* code, unsigned int codeLength, unsigned const char* publicN, unsigned int nLength) const;
	    
	    os::smart_ptr<number> decode(os::smart_ptr<number> code) const;
	};
	//RSA Generator
	class RSAKeyGenerator
	{
		publicRSA* master;
	
	public:
		integer p;
		integer q;
		
		RSAKeyGenerator(publicRSA& m);
		virtual ~RSAKeyGenerator(){}
		
		integer generatePrime();
		void pushValues();
	};
  
};

#endif
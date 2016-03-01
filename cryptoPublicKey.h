/**
 * @file   cryptoPublicKey.h
 * @author Jonathan Bedard
 * @date   2/29/2016
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
	/** @brief Base public-key class
	 *
	 * Class which defines the general
	 * structure of a public-private
	 * key pair.  The class does not
	 * define the specifics of the algorithm.
	 */
    class publicKey: public os::savable
	{
		/**@ brief Size of the keys used
		 */
		uint16_t _size;
		/**@ brief ID of algorithm used
		 */
		uint16_t _algorithm;
		/**@ brief Number of historical keys to keep
		 */
        uint16_t _history;

		/** @brief Symetric key for encryption
		 */
		unsigned char* _key;
		/** @brief Length of symetric key
		 */
		unsigned int _keyLen;
		/**@ brief Algorithm used for encryption
		 */
		os::smart_ptr<streamPackageFrame> fePackage;
		/**@ brief Name of file this key is saved to
		 */
		std::string _fileName;
		/**@ brief Mutex for replacing the keys
		 */
		os::multiLock keyLock;
	protected:
		/**@ brief Public key
		 */
        os::smart_ptr<number> n;
		/**@ brief Private key
		 */
        os::smart_ptr<number> d;
		/**@ brief Date/time keys created
		 */
		uint64_t _timestamp;
        
		/**@ brief List of old public keys
		 */
        os::unsortedList<number> oldN;
		/**@ brief List of old private keys
		 */
        os::unsortedList<number> oldD;
		/**@ brief List of timestamps for old pairs
		 */
		os::unsortedList<uint64_t> _timestamps;

		publicKey(uint16_t algo,uint16_t sz=size::public512);
        publicKey(const publicKey& ky);
		publicKey(os::smart_ptr<number> _n,os::smart_ptr<number> _d,uint16_t algo,uint16_t sz=size::public512,uint64_t tms=os::getTimestamp());
		publicKey(uint16_t algo,std::string fileName,std::string password="",os::smart_ptr<streamPackageFrame> stream_algo=NULL);
		publicKey(uint16_t algo,std::string fileName,unsigned char* key,unsigned int keyLen,os::smart_ptr<streamPackageFrame> stream_algo=NULL);
    
		inline void writeLock() {keyLock.lock();}
		inline void writeUnlock() {keyLock.unlock();}

		int compare(const publicKey& cmp) const;
        
        void pushOldKeys(os::smart_ptr<number> n, os::smart_ptr<number> d,uint64_t ts);
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
		uint64_t timestamp() const {return _timestamp;}
		os::smart_ptr<number> getOldN(unsigned int history=0);
		os::smart_ptr<number> getOldD(unsigned int history=0);
		uint64_t getOldTimestamp(unsigned int history=0);
		virtual void generateNewKeys();
        virtual bool generating() {return false;}
		inline static uint16_t staticAlgorithm() {return algo::publicNULL;}
        inline static std::string staticAlgorithmName() {return "NULL Public Key";}
		inline uint16_t algorithm() const {return _algorithm;}
		inline virtual std::string algorithmName() const {return publicKey::staticAlgorithmName();}
        uint16_t size() const {return _size;}

		inline void readLock() {keyLock.increment();}
		inline void readUnlock() {keyLock.decrement();}
        
        //History
        void setHistory(uint16_t hist);
        inline uint16_t history() const {return _history;}

		//File loading and saving
		void save();
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

		/** @brief Compares equality by size and algorithm
		 * @return boolean '=='
		 */
		bool operator==(const publicKey& cmp) const {return 0==compare(cmp);}
		/** @brief Compares equality by size and algorithm
		 * @return boolean '!='
		 */
		bool operator!=(const publicKey& cmp) const {return 0!=compare(cmp);}
		/** @brief Compares equality by size and algorithm
		 * @return boolean '<'
		 */
		bool operator<(const publicKey& cmp) const {return -1==compare(cmp);}
		/** @brief Compares equality by size and algorithm
		 * @return boolean '>'
		 */
		bool operator>(const publicKey& cmp) const {return 1==compare(cmp);}
		/** @brief Compares equality by size and algorithm
		 * @return boolean '<='
		 */
		bool operator<=(const publicKey& cmp) const {return 1!=compare(cmp);}
		/** @brief Compares equality by size and algorithm
		 * @return boolean '>='
		 */
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
	    publicRSA(os::smart_ptr<integer> _n,os::smart_ptr<integer> _d,uint16_t sz=size::public512,uint64_t tms=os::getTimestamp());
		publicRSA(uint32_t* _n,uint32_t* _d,uint16_t sz=size::public512,uint64_t tms=os::getTimestamp());
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
//Primary author: Jonathan Bedard
//Certified working 1/16/2016

#ifndef BINARY_ENCRYPTION_H
#define BINARY_ENCRYPTION_H
 
#include "streamPackage.h"
#include "cryptoError.h"

namespace crypto {

	//Binary file encryptor
	class binaryEncryptor: public errorSender
	{
		os::smart_ptr<streamPackageFrame> _streamAlgorithm;
		os::smart_ptr<streamCipher> currentCipher;
		bool _state;
		bool _finished;
		std::string _fileName;
		std::ofstream output;

		//Builds the file for encryption (with error logging)
		void build(unsigned char* key,unsigned int keyLen);

	public:
		binaryEncryptor(std::string file_name,std::string password,os::smart_ptr<streamPackageFrame> stream_algo=NULL);
		binaryEncryptor(std::string file_name,unsigned char* key,unsigned int keyLen,os::smart_ptr<streamPackageFrame> stream_algo=NULL);

		//Action functions
		void write(unsigned char data);
		void write(const unsigned char* data,unsigned int dataLen);
		void close();

		//Get Functions
		const std::string& fileName() const {return _fileName;}
		const os::smart_ptr<streamPackageFrame> streamAlgorithm() const {return _streamAlgorithm;}
		bool good() const{return _state;}
		bool finished() const{return _finished;}

		virtual ~binaryEncryptor(){close();}
	};
	//Binary file decryptor
	class binaryDecryptor: public errorSender
	{
		os::smart_ptr<streamPackageFrame> _streamAlgorithm;
		os::smart_ptr<streamCipher> currentCipher;
		bool _state;
		bool _finished;
		std::string _fileName;
		std::ifstream input;
		unsigned long _bytesLeft;

		//Builds the file for decryption (with error logging)
		void build(unsigned char* key,unsigned int keyLen);
	public:
		binaryDecryptor(std::string file_name,std::string password);
		binaryDecryptor(std::string file_name,unsigned char* key,unsigned int keyLen);

		//Action functions
		unsigned char read();
		unsigned int read(unsigned char* data,unsigned int dataLen);
		void close();

		//Get Functions
		const std::string& fileName() const {return _fileName;}
		const os::smart_ptr<streamPackageFrame> streamAlgorithm() const {return _streamAlgorithm;}
		bool good() const{return _state;}
		bool finished() const{return _finished;}
		unsigned long bytesLeft() const {return _bytesLeft;}

		virtual ~binaryDecryptor(){close();}
	};
}

#endif

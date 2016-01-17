//Primary author: Jonathan Bedard
//Certified working 1/16/2016

#ifndef BINARY_ENCRYPTION_CPP
#define BINARY_ENCRYPTION_CPP

#include <string>
#include <stdint.h>
#include "binaryEncryption.h"

namespace crypto {
   
/*------------------------------------------------------------
     Binary Encryption
 ------------------------------------------------------------*/

	//Constructor with password
	binaryEncryptor::binaryEncryptor(std::string file_name,std::string password,os::smart_ptr<streamPackageFrame> stream_algo):
		output(file_name,std::ios::binary)
	{
		_fileName=file_name;
		_state=true;
		_finished=false;
		_streamAlgorithm=stream_algo;
		if(!output.good())
		{
			logError(errorPointer(new fileOpenError,os::shared_type));
			output.close();
			_state=false;
		}
		else build((unsigned char*)password.c_str(),password.length());
	}
	//Constructor with raw array
	binaryEncryptor::binaryEncryptor(std::string file_name,unsigned char* key,unsigned int keyLen,os::smart_ptr<streamPackageFrame> stream_algo):
		output(file_name,std::ios::binary)
	{
		_fileName=file_name;
		_state=true;
		_finished=false;
		_streamAlgorithm=stream_algo;
		if(!output.good())
		{
			logError(errorPointer(new fileOpenError(),os::shared_type));
			output.close();
			_state=false;
		}
		else build(key,keyLen);
	}
	//Build (triggered by encryptor)
	void binaryEncryptor::build(unsigned char* key,unsigned int keyLen)
	{
		try
		{
			//Check key size first
			if(keyLen<1) throw errorPointer(new passwordSmallError(),os::shared_type);
			if(!_streamAlgorithm) throw errorPointer(new illegalAlgorithmBind("NULL Stream"),os::shared_type);

			//Attempt to output header
			uint16_t valHld;
			unsigned char head[8];
				//Public key
				valHld=0;
			valHld=os::to_comp_mode(valHld);
			memcpy(head,&valHld,2);

			//Stream
			valHld=os::to_comp_mode(_streamAlgorithm->streamAlgorithm());
			memcpy(head+2,&valHld,2);

			//Hash
			valHld=os::to_comp_mode(_streamAlgorithm->hashAlgorithm());
			memcpy(head+4,&valHld,2);
			valHld=os::to_comp_mode(_streamAlgorithm->hashSize());
			memcpy(head+6,&valHld,2);
			output.write((char*)head,8);
			if(!output.good()) throw errorPointer(new fileOpenError(),os::shared_type);

			//Hash password and write it to file
			hash hsh=_streamAlgorithm->hashData(key,keyLen);
			output.write((char*)hsh.data(),hsh.size());
			if(!output.good()) throw errorPointer(new fileOpenError(),os::shared_type);

			//Generate stream cipher
			currentCipher=_streamAlgorithm->buildStream(key,keyLen);
			if(!currentCipher) throw errorPointer(new illegalAlgorithmBind("NULL build stream"),os::shared_type);
		}
		catch(errorPointer ptr)
		{
			logError(ptr);
			output.close();
			_state=false;
		}
	}
	
	//Write data
	void binaryEncryptor::write(unsigned char data)
	{
		if(!_state)
		{
			logError(errorPointer(new actionOnFileError(),os::shared_type));
			return;
		}
		if(_finished)
		{
			logError(errorPointer(new actionOnFileClosed(),os::shared_type));
			return;
		}
		output.put(data^currentCipher->getNext());
		if(!output.good())
		{
			logError(errorPointer(new fileOpenError(),os::shared_type));
			output.close();
			_state=false;
		}
	}
	//Write data
	void binaryEncryptor::write(const unsigned char* data,unsigned int dataLen)
	{
		if(!_state)
		{
			logError(errorPointer(new actionOnFileError(),os::shared_type));
			return;
		}
		if(_finished)
		{
			logError(errorPointer(new actionOnFileClosed(),os::shared_type));
			return;
		}
		unsigned char* arr=new unsigned char[dataLen];
		for(unsigned int i=0;i<dataLen;i++)
			arr[i]=data[i]^currentCipher->getNext();
		output.write((char*)arr,dataLen);
		delete [] arr;
		if(!output.good())
		{
			logError(errorPointer(new fileOpenError(),os::shared_type));
			output.close();
			_state=false;
		}
	}
	//Close current binary file encryptor
	void binaryEncryptor::close()
	{
		if(!_state)
		{
			logError(errorPointer(new actionOnFileError(),os::shared_type));
			return;
		}
		if(_finished)
		{
			logError(errorPointer(new actionOnFileClosed(),os::shared_type));
			return;
		}
		_finished=true;
		currentCipher=NULL;
		output.close();
	}

/*------------------------------------------------------------
     Binary Decryption
 ------------------------------------------------------------*/

	//Binary decryptor string password constructor
	binaryDecryptor::binaryDecryptor(std::string file_name,std::string password):
		input(file_name,std::ios::binary)
	{
		_fileName=file_name;
		_state=true;
		_finished=false;
		_bytesLeft=0;
		if(!input.good())
		{
			logError(errorPointer(new fileOpenError,os::shared_type));
			input.close();
			_state=false;
		}
		else build((unsigned char*)password.c_str(),password.length());
	}
	//Binary decryptor byte array constructor
	binaryDecryptor::binaryDecryptor(std::string file_name,unsigned char* key,unsigned int keyLen):
		input(file_name,std::ios::binary)
	{
		_fileName=file_name;
		_state=true;
		_finished=false;
		_bytesLeft=0;
		if(!input.good())
		{
			logError(errorPointer(new fileOpenError,os::shared_type));
			input.close();
			_state=false;
		}
		else build(key,keyLen);
	}
	//Builds the file for decryption (with error logging)
	void binaryDecryptor::build(unsigned char* key,unsigned int keyLen)
	{
		try
		{
			//Check key size first
			if(keyLen<1) throw errorPointer(new passwordSmallError(),os::shared_type);

			//Bind file length
			std::streampos fsize;
			fsize = input.tellg();
			input.seekg( 0, std::ios::end );
			_bytesLeft = input.tellg() - fsize;
			input.seekg (0, std::ios::beg);

			//Data values
			uint16_t publicAlgoVal;
			uint16_t streamAlgoVal;
			uint16_t hashAlgoVal;
			uint16_t hashSizeVal;

			//Read data
			unsigned char buffer[64];
			input.read((char*)buffer,8);
			_bytesLeft-=8;
			memcpy(&publicAlgoVal,buffer,2);
			memcpy(&streamAlgoVal,buffer+2,2);
			memcpy(&hashAlgoVal,buffer+4,2);
			memcpy(&hashSizeVal,buffer+6,2);

			publicAlgoVal=os::from_comp_mode(publicAlgoVal);
			streamAlgoVal=os::from_comp_mode(streamAlgoVal);
			hashAlgoVal=os::from_comp_mode(hashAlgoVal);
			hashSizeVal=os::from_comp_mode(hashSizeVal);

			//Bind algorithm
			if(!input.good()) throw errorPointer(new fileOpenError(),os::shared_type);
			_streamAlgorithm=streamPackageTypeBank::singleton()->findStream(streamAlgoVal,hashAlgoVal);
			if(!_streamAlgorithm) throw errorPointer(new illegalAlgorithmBind("Stream ID: "+std::to_string(streamAlgoVal)+", Hash ID: "+std::to_string(hashAlgoVal)),os::shared_type);
			_streamAlgorithm=_streamAlgorithm->getCopy();
			_streamAlgorithm->setHashSize(hashSizeVal);

			//Pull hash
			hash calcHash=_streamAlgorithm->hashData(key,keyLen);
			input.read((char*)buffer,calcHash.size());
			_bytesLeft-=calcHash.size();
			if(!input.good()) throw errorPointer(new fileOpenError(),os::shared_type);
			hash pullHash=_streamAlgorithm->hashCopy(buffer);

			//Check hash
			if(calcHash!=pullHash) throw errorPointer(new hashCompareError(),os::shared_type);

			//Construct stream
			currentCipher=_streamAlgorithm->buildStream(key,keyLen);
		}
		catch(errorPointer ptr)
		{
			logError(ptr);
			input.close();
			_state=false;
			_bytesLeft=0;
		}
	}
	
	//Read character
	unsigned char binaryDecryptor::read()
	{
		if(!_state)
		{
			logError(errorPointer(new actionOnFileError(),os::shared_type));
			return 0;
		}
		if(_finished)
		{
			logError(errorPointer(new actionOnFileClosed(),os::shared_type));
			return 0;
		}
		unsigned char ret=input.get()^currentCipher->getNext();
		_bytesLeft--;
		if(_bytesLeft<=0||!input.good())
		{
			_bytesLeft=0;
			if(!input.good())
			{
				logError(errorPointer(new fileOpenError(),os::shared_type));
				_state=false;
			}
			else _finished=true;
			input.close();
		}
		return ret;
	}
	//Read byte array
	unsigned int binaryDecryptor::read(unsigned char* data,unsigned int dataLen)
	{
		if(!_state)
		{
			logError(errorPointer(new actionOnFileError(),os::shared_type));
			return 0;
		}
		if(_finished)
		{
			logError(errorPointer(new actionOnFileClosed(),os::shared_type));
			return 0;
		}
		unsigned int readTarg=dataLen;
		if(readTarg>_bytesLeft) readTarg=_bytesLeft;
		input.read((char*) data,dataLen);

		//Decrypt data
		for(unsigned int i=0;i<readTarg;i++)
			data[i]=data[i]^currentCipher->getNext();
		_bytesLeft-=readTarg;
		if(_bytesLeft<=0||!input.good())
		{
			_bytesLeft=0;
			if(!input.good())
			{
				logError(errorPointer(new fileOpenError(),os::shared_type));
				_state=false;
			}
			else _finished=true;
			input.close();
		}
		return readTarg;
	}
	//Close binary decryptor
	void binaryDecryptor::close()
	{
		if(!_state)
		{
			logError(errorPointer(new actionOnFileError(),os::shared_type));
			return;
		}
		if(_finished)
		{
			logError(errorPointer(new actionOnFileClosed(),os::shared_type));
			return;
		}
		_finished=true;
		currentCipher=NULL;
		input.close();
		_bytesLeft=0;
	}
}

#endif

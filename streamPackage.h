//Primary author: Jonathan Bedard
//Certified working 1/10/2016

#ifndef STREAM_PACKAGE_H
#define STREAM_PACKAGE_H
 
#include <string>
#include <stdint.h>
#include <vector>
#include "RC4_Hash.h"
#include "streamTest.h"

namespace crypto {
    
    //Stream package frame
    class streamPackageFrame
    {
    protected:
        uint16_t _hashSize;
    public:
        streamPackageFrame(uint16_t hashSize=size::hash256){_hashSize=hashSize;}
        virtual ~streamPackageFrame(){}
        
        virtual os::smart_ptr<streamPackageFrame> getCopy() {return NULL;}
        
        virtual hash hashData(unsigned char* data, uint32_t len) const {return xorHash();}
        virtual hash hashCopy(unsigned char* data) const {return xorHash(data,_hashSize);}
        virtual os::smart_ptr<streamCipher> buildStream(unsigned char* data, uint32_t len) const {return NULL;}
    };
    //Stream Encryption type
    template <class streamType, class hashType>
    class streamPackage: public streamPackageFrame
    {
    public:
        streamPackage(uint16_t hashSize=size::hash256):streamPackageFrame(hashSize){}
        virtual ~streamPackage(){}
        os::smart_ptr<streamPackageFrame> getCopy() const {return os::smart_ptr<streamPackageFrame>(new streamPackage<streamType,hashType>(_hashSize),os::shared_type);}
        
        void setHashSize(uint16_t hashSize) {_hashSize=hashSize;}
        uint16_t hashSize() const {return _hashSize;}
        
        //Preform the hash
        hash hashData(unsigned char* data, uint32_t len) const
        {
            if(_hashSize==size::hash64)
                return hashType::hash64Bit(data,len);
            else if(_hashSize==size::hash128)
                return hashType::hash128Bit(data,len);
            else if(_hashSize==size::hash256)
                return hashType::hash256Bit(data,len);
            else if(_hashSize==size::hash512)
                return hashType::hash512Bit(data,len);
            return hashType::hash256Bit(data,len);
        }
        hash hashCopy(unsigned char* data) const {return rc4Hash(data,_hashSize);}
        
        //Build a stream
        os::smart_ptr<streamCipher> buildStream(unsigned char* data, uint32_t len) const
        {return os::smart_ptr<streamCipher>(new streamType(data,len),os::shared_type);}
        
        //Return stream type name
        std::string streamAlgorithmName() const {return streamType::staticAlgorithmName();}
        uint16_t streamAlgorithm() const {return streamType::staticAlgorithm();}
        
        //Return hash type name
        std::string hashAlgorithmName() const {return hashType::staticAlgorithmName();}
        uint16_t hashAlgorithm() const {return hashType::staticAlgorithm();}
    };
    
    //Encryption stream type bank
    class streamPackageTypeBank
    {
        std::vector<os::smart_ptr<std::vector<os::smart_ptr<streamPackageFrame> > > > packageVector;
        
        streamPackageTypeBank();
    public:
        virtual ~streamPackageTypeBank(){}
        static os::smart_ptr<streamPackageTypeBank> singleton();
        
        void setDefaultPackage(os::smart_ptr<streamPackageFrame> package);
        void pushPackage(os::smart_ptr<streamPackageFrame> package);
        os::smart_ptr<streamPackageFrame> findStream(uint16_t streamID,uint16_t hashID);
    };
}

#endif
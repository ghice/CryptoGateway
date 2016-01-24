//Primary author: Jonathan Bedard
//Certified working 1/23/2016

#ifndef PUBLIC_KEY_PACKAGE_H
#define PUBLIC_KEY_PACKAGE_H
 
#include "cryptoPublicKey.h"

namespace crypto {
    //Public key package frame
    class publicKeyPackageFrame
    {
    protected:
        uint16_t _publicSize;
    public:
        publicKeyPackageFrame(uint16_t publicSize=size::public512){_publicSize=publicSize;}
        virtual ~publicKeyPackageFrame(){}
        
        virtual os::smart_ptr<publicKeyPackageFrame> getCopy() const {return NULL;}
        
        virtual os::smart_ptr<publicKey> generate() const {return NULL;}
        virtual os::smart_ptr<publicKey> bindKeys(os::smart_ptr<integer> _n,os::smart_ptr<integer> _d) const {return NULL;}
        virtual os::smart_ptr<publicKey> bindKeys(uint32_t* _n,uint32_t* _d) const {return NULL;}
        virtual os::smart_ptr<publicKey> openFile(std::string fileName,std::string password) const {return NULL;}
        virtual os::smart_ptr<publicKey> openFile(std::string fileName,unsigned char* key,unsigned int keyLen) const {return NULL;}
        
        //Return data info
        virtual std::string algorithmName() const {return "NULL public key";}
        virtual uint16_t algorithm() const {return algo::publicNULL;}
        
        void setKeySize(uint16_t publicSize) {_publicSize=publicSize;}
        uint16_t keySize() const {return _publicSize;}
    };
    
    //Public key type bank
    class publicKeyTypeBank
    {
        os::smart_ptr<publicKeyPackageFrame> _defaultPackage;
        std::vector<os::smart_ptr<publicKeyPackageFrame> > packageVector;
        
        publicKeyTypeBank();
    public:
        virtual ~publicKeyTypeBank(){}
        static os::smart_ptr<publicKeyTypeBank> singleton();
        
        void setDefaultPackage(os::smart_ptr<publicKeyPackageFrame> package);
        const os::smart_ptr<publicKeyPackageFrame> defaultPackage() const {return _defaultPackage;}
        void pushPackage(os::smart_ptr<publicKeyPackageFrame> package);
        const os::smart_ptr<publicKeyPackageFrame> findPublicKey(uint16_t pkID) const;
        const os::smart_ptr<publicKeyPackageFrame> findPublicKey(const std::string& pkName) const;
    };
}

#endif

//Primary author: Jonathan Bedard
//Certified working 1/26/2016

#ifndef XML_ENCRYPTION_H
#define XML_ENCRYPTION_H
 
#include "streamPackage.h"
#include "publicKeyPackage.h"

namespace crypto {

    //XML encryption output
	bool EXML_Output(std::string path, os::smartXMLNode head, unsigned char* symKey,unsigned int passwordLength, os::smart_ptr<streamPackageFrame> spf=NULL);
    bool EXML_Output(std::string path, os::smartXMLNode head, std::string password, os::smart_ptr<streamPackageFrame> spf=NULL);
    bool EXML_Output(std::string path, os::smartXMLNode head, os::smart_ptr<publicKey> pbk, os::smart_ptr<streamPackageFrame> spf=NULL);
    
    //XML decryption input
	os::smartXMLNode EXML_Input(std::string path, unsigned char* symKey,unsigned int passwordLength);
    os::smartXMLNode EXML_Input(std::string path, std::string password);
    os::smartXMLNode EXML_Input(std::string path, os::smart_ptr<publicKey> pbk);
}

#endif

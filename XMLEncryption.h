/**
 * @file	XMLEncryption.h
 * @author	Jonathan Bedard
 * @date   	5/19/2016
 * @brief	Provides structure to encrypt an XML save file
 * @bug	None
 *
 * Provides functions to save and load XML trees in
 * encrypted files.
 **/

#ifndef XML_ENCRYPTION_H
#define XML_ENCRYPTION_H
 
#include "streamPackage.h"
#include "publicKeyPackage.h"

namespace crypto {

	///@cond INTERNAL
	    class keyBank;
		class nodeGroup;
    ///@endcond

    //XML encryption output
	bool EXML_Output(std::string path, os::smartXMLNode head, unsigned char* symKey,unsigned int passwordLength, os::smart_ptr<streamPackageFrame> spf=NULL);
    bool EXML_Output(std::string path, os::smartXMLNode head, std::string password, os::smart_ptr<streamPackageFrame> spf=NULL);

    bool EXML_Output(std::string path, os::smartXMLNode head, os::smart_ptr<publicKey> pbk,unsigned int lockType=file::PRIVATE_UNLOCK,os::smart_ptr<streamPackageFrame> spf=NULL);
	bool EXML_Output(std::string path, os::smartXMLNode head, os::smart_ptr<number> publicKey,unsigned int pkAlgo,unsigned int pkSize,os::smart_ptr<streamPackageFrame> spf=NULL);

    //XML decryption input
	os::smartXMLNode EXML_Input(std::string path, unsigned char* symKey,unsigned int passwordLength);
    os::smartXMLNode EXML_Input(std::string path, std::string password);
	os::smartXMLNode EXML_Input(std::string path, os::smart_ptr<publicKey> pbk,os::smart_ptr<keyBank> kyBank,os::smart_ptr<nodeGroup>& author);
    os::smartXMLNode EXML_Input(std::string path, os::smart_ptr<publicKey> pbk);
	os::smartXMLNode EXML_Input(std::string path, os::smart_ptr<keyBank> kyBank);
	os::smartXMLNode EXML_Input(std::string path, os::smart_ptr<keyBank> kyBank,os::smart_ptr<nodeGroup>& author);
}

#endif

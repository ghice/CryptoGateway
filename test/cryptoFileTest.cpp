/**
 * @file   test/cryptoFileTest.cpp
 * @author Jonathan Bedard
 * @date   5/26/2016
 * @brief  Implementation for cryptographic file testing
 * @bug No known bugs.
 *
 * This file implements a series of tests designed
 * to confirm the stability of cryptographic save file
 * and load file functions.
 *
 */

///@cond INTERNAL

#ifndef CRYPTO_FILE_TEST_CPP
#define CRYPTO_FILE_TEST_CPP

#include <string>
#include <stdint.h>
#include "cryptoFileTest.h"
#include "publicKeyPackage.h"
#include "testKeyGeneration.h"
#include "XMLEncryption.h"
#include "keyBank.h"

using namespace crypto;
using namespace test;

/*------------------------------------------------------------
    Binary File Tests
 ------------------------------------------------------------*/

	//Package test
	void packageTest() throw(os::smart_ptr<std::exception>)
	{
		std::string locString = "cryptoFileTest.cpp, packageTest()";

		os::smart_ptr<streamPackageFrame> pck=streamPackageTypeBank::singleton()->findStream(algo::streamNULL,algo::hashNULL);
		if(pck)
			throw os::smart_ptr<std::exception>(new generalTestException("Stream NULL and Hash NULL returned algorithm",locString),os::shared_type);
		pck=streamPackageTypeBank::singleton()->findStream(algo::streamRC4,algo::hashRC4);

		if(!pck)
			throw os::smart_ptr<std::exception>(new generalTestException("No default stream and hash",locString),os::shared_type);
		
		if(pck!=streamPackageTypeBank::singleton()->findStream(RCFour::staticAlgorithmName(),rc4Hash::staticAlgorithmName()))
			throw os::smart_ptr<std::exception>(new generalTestException("Default package does not match known default package",locString),os::shared_type);
	}

	//Binary file test
	binaryFileSaveTest::binaryFileSaveTest(os::smart_ptr<streamPackageFrame> spf):
		singleTest(spf->streamAlgorithmName()+", "+spf->hashAlgorithmName()+"("+std::to_string((long long unsigned int)spf->hashSize()*8)+"): Binary File")
	{
		streamPackage=spf;
	}
	void binaryFileSaveTest::test() throw(os::smart_ptr<std::exception>)
	{
		std::string locString = "cryptoFileTest.cpp, binaryFileSaveTest::test()";

		//Bind data
		unsigned char refData[100];
		unsigned char readData[100];
		for(int i=0;i<100;++i)
			refData[i]=rand();

		try
		{
			//Write data
			binaryEncryptor binEn("testExample.bin","binaryPassword",streamPackage);
			if(!binEn.good())
				throw os::smart_ptr<std::exception>(new generalTestException("Failed to init binary writer",locString),os::shared_type);
			binEn.write(refData,100);
			binEn.close();

			//Decryptor
			binaryDecryptor binDe("testExample.bin","binaryPassword");
			if(!binDe.good())
				throw os::smart_ptr<std::exception>(new generalTestException("Failed to init binary reader",locString),os::shared_type);
			if(100!=binDe.read(readData,100))
				throw os::smart_ptr<std::exception>(new generalTestException("Failed to init binary reader",locString),os::shared_type);

			//Compare reference and read data
			for(int i=0;i<100;++i)
			{
				if(refData[i]!=readData[i])
					throw os::smart_ptr<std::exception>(new generalTestException("Reference-read mis-match",locString),os::shared_type);
			}
		}
		catch(os::smart_ptr<std::exception> e)
		{
			os::delete_file("testExample.bin");
			throw e;
		}
		catch(...)
		{
			os::delete_file("testExample.bin");
			throw os::smart_ptr<std::exception>(new generalTestException("Unknown exception type",locString),os::shared_type);
		}
		os::delete_file("testExample.bin");
	}
	
	//Public key binary file tests
	publicKeyFileSaveTest::publicKeyFileSaveTest(os::smart_ptr<crypto::publicKey> pk):
		singleTest(pk->algorithmName()+" "+std::to_string((long long unsigned int)32*pk->size())+" bit: Binary File")
	{
		pubkey=pk;
	}
	void publicKeyFileSaveTest::test() throw(os::smart_ptr<std::exception>)
	{
		std::string locString = "cryptoFileTest.cpp, binaryFileSaveTest::test()";

		//Bind data
		unsigned char refData[100];
		unsigned char readData[100];
		for(int i=0;i<100;++i)
			refData[i]=rand();

		try
		{
			//Write data
			binaryEncryptor binEn("testExample.bin",pubkey);
			if(!binEn.good())
				throw os::smart_ptr<std::exception>(new generalTestException("Failed to init binary writer",locString),os::shared_type);
			binEn.write(refData,100);
			binEn.close();

			//Decryptor
			binaryDecryptor binDe("testExample.bin",pubkey);
			if(!binDe.good())
				throw os::smart_ptr<std::exception>(new generalTestException("Failed to init binary reader",locString),os::shared_type);
			if(100!=binDe.read(readData,100))
				throw os::smart_ptr<std::exception>(new generalTestException("Failed to init binary reader",locString),os::shared_type);

			//Compare reference and read data
			for(int i=0;i<100;++i)
			{
				if(refData[i]!=readData[i])
					throw os::smart_ptr<std::exception>(new generalTestException("Reference-read mis-match",locString),os::shared_type);
			}
		}
		catch(os::smart_ptr<std::exception> e)
		{
			os::delete_file("testExample.bin");
			throw e;
		}
		catch(...)
		{
			os::delete_file("testExample.bin");
			throw os::smart_ptr<std::exception>(new generalTestException("Unknown exception type",locString),os::shared_type);
		}
		os::delete_file("testExample.bin");
	}

	//Public header
	void binaryPublicHeader() throw(os::smart_ptr<std::exception>)
	{
		std::string locString = "cryptoFileTest.cpp, binaryPublicHeader()";

		//Bind data
		unsigned char refData[100];
		unsigned char readData[100];
		for(int i=0;i<100;++i)
			refData[i]=rand();

		try
		{
			//Write data
			uint32_t *n,*d;
			os::smart_ptr<publicKeyPackageFrame> pkg=publicKeyTypeBank::singleton()->defaultPackage();
			if(!pkg) return;
			pkg=pkg->getCopy();

			pkg->setKeySize(size::public128);
			findKeysRaw(n,d,pkg->algorithm(),pkg->keySize());
			os::smart_ptr<publicKey> kys=pkg->bindKeys(n,d);
			binaryEncryptor binEn("testExample.bin",kys,file::PUBLIC_UNLOCK);
			if(!binEn.good())
				throw os::smart_ptr<std::exception>(new generalTestException("Failed to init binary writer",locString),os::shared_type);
			binEn.write(refData,100);
			binEn.close();

			//Decryptor
			binaryDecryptor binDe("testExample.bin",kys);
			if(!binDe.good())
				throw os::smart_ptr<std::exception>(new generalTestException("Failed to init binary reader",locString),os::shared_type);
			if(100!=binDe.read(readData,100))
				throw os::smart_ptr<std::exception>(new generalTestException("Failed to init binary reader",locString),os::shared_type);

			//Compare reference and read data
			for(int i=0;i<100;++i)
			{
				if(refData[i]!=readData[i])
					throw os::smart_ptr<std::exception>(new generalTestException("Reference-read mis-match",locString),os::shared_type);
			}

			//Decrypt again
			avlKeyBank kybnk;
			os::smart_ptr<nodeGroup> ng=kybnk.addPair("No-G","Me",kys->getN(),kys->algorithm(),kys->size());
			binaryDecryptor binDe2("testExample.bin",&kybnk);
			if(!binDe2.good())
				throw os::smart_ptr<std::exception>(new generalTestException("Failed to init binary reader (signing case)",locString),os::shared_type);
			if(100!=binDe2.read(readData,100))
				throw os::smart_ptr<std::exception>(new generalTestException("Failed to init binary reader (signing case)",locString),os::shared_type);
			if(!binDe2.author() || binDe2.author()->name() != ng->name())
				throw os::smart_ptr<std::exception>(new generalTestException("Failed to confirm author",locString),os::shared_type);

			//Compare reference and read data
			for(int i=0;i<100;++i)
			{
				if(refData[i]!=readData[i])
					throw os::smart_ptr<std::exception>(new generalTestException("Reference-read mis-match",locString),os::shared_type);
			}
		}
		catch(os::smart_ptr<std::exception> e)
		{
			os::delete_file("testExample.bin");
			throw e;
		}
		catch(...)
		{
			os::delete_file("testExample.bin");
			throw os::smart_ptr<std::exception>(new generalTestException("Unknown exception type",locString),os::shared_type);
		}
		os::delete_file("testExample.bin");
	}
	//Public header
	void binaryDoubleLock() throw(os::smart_ptr<std::exception>)
	{
		std::string locString = "cryptoFileTest.cpp, binaryDoubleLock()";

		//Bind data
		unsigned char refData[100];
		unsigned char readData[100];
		for(int i=0;i<100;++i)
			refData[i]=rand();

		try
		{
			//Write data
			uint32_t *n,*d;
			os::smart_ptr<publicKeyPackageFrame> pkg=publicKeyTypeBank::singleton()->defaultPackage();
			if(!pkg) return;
			pkg=pkg->getCopy();

			pkg->setKeySize(size::public128);
			findKeysRaw(n,d,pkg->algorithm(),pkg->keySize());
			os::smart_ptr<publicKey> kys=pkg->bindKeys(n,d);
			binaryEncryptor binEn("testExample.bin",kys,file::DOUBLE_LOCK);
			if(!binEn.good())
				throw os::smart_ptr<std::exception>(new generalTestException("Failed to init binary writer",locString),os::shared_type);
			binEn.write(refData,100);
			binEn.close();

			//Decryptor
			binaryDecryptor binDe("testExample.bin",kys);
			if(!binDe.good())
				throw os::smart_ptr<std::exception>(new generalTestException("Failed to init binary reader",locString),os::shared_type);
			if(100!=binDe.read(readData,100))
				throw os::smart_ptr<std::exception>(new generalTestException("Failed to init binary reader",locString),os::shared_type);

			//Compare reference and read data
			for(int i=0;i<100;++i)
			{
				if(refData[i]!=readData[i])
					throw os::smart_ptr<std::exception>(new generalTestException("Reference-read mis-match",locString),os::shared_type);
			}

		}
		catch(os::smart_ptr<std::exception> e)
		{
			os::delete_file("testExample.bin");
			throw e;
		}
		catch(...)
		{
			os::delete_file("testExample.bin");
			throw os::smart_ptr<std::exception>(new generalTestException("Unknown exception type",locString),os::shared_type);
		}
		os::delete_file("testExample.bin");
	}

/*------------------------------------------------------------
     Crypto File Test
 ------------------------------------------------------------*/
	cryptoFileTestSuite::cryptoFileTestSuite():
		testSuite("Files and Packages")
	{
		pushTest("Package",&packageTest);
		pushTestPackage(streamPackageTypeBank::singleton()->findStream(algo::streamRC4,algo::hashRC4));
		pushTestPackage(publicKeyTypeBank::singleton()->findPublicKey(crypto::algo::publicRSA));
		pushTest("Public Signing",&binaryPublicHeader);
		pushTest("Double Lock",&binaryDoubleLock);
	}
	//Attempt to push packages to test
	void cryptoFileTestSuite::pushTestPackage(os::smart_ptr<streamPackageFrame> spf)
	{
		if(!spf) return;
		os::smart_ptr<streamPackageFrame> sp=spf->getCopy();
		sp->setHashSize(size::hash64);
		pushTest(os::smart_ptr<singleTest>(new binaryFileSaveTest(sp),os::shared_type));

		sp=spf->getCopy();
		sp->setHashSize(size::hash128);
		pushTest(os::smart_ptr<singleTest>(new binaryFileSaveTest(sp),os::shared_type));

		sp=spf->getCopy();
		sp->setHashSize(size::hash256);
		pushTest(os::smart_ptr<singleTest>(new binaryFileSaveTest(sp),os::shared_type));

		sp=spf->getCopy();
		sp->setHashSize(size::hash512);
		pushTest(os::smart_ptr<singleTest>(new binaryFileSaveTest(sp),os::shared_type));
	}
	//Attempt to push a package to test by public ID
	void cryptoFileTestSuite::pushTestPackage(os::smart_ptr<publicKeyPackageFrame> pkg)
	{
		uint32_t *n,*d;
		if(!pkg) return;
		pkg=pkg->getCopy();

		pkg->setKeySize(size::public128);
		findKeysRaw(n,d,pkg->algorithm(),pkg->keySize());
		pushTest(os::smart_ptr<singleTest>(new publicKeyFileSaveTest(pkg->bindKeys(n,d)),os::shared_type));

		pkg->setKeySize(size::public256);
		findKeysRaw(n,d,pkg->algorithm(),pkg->keySize());
		pushTest(os::smart_ptr<singleTest>(new publicKeyFileSaveTest(pkg->bindKeys(n,d)),os::shared_type));

		pkg->setKeySize(size::public512);
		findKeysRaw(n,d,pkg->algorithm(),pkg->keySize());
		pushTest(os::smart_ptr<singleTest>(new publicKeyFileSaveTest(pkg->bindKeys(n,d)),os::shared_type));

		pkg->setKeySize(size::public1024);
		findKeysRaw(n,d,pkg->algorithm(),pkg->keySize());
		pushTest(os::smart_ptr<singleTest>(new publicKeyFileSaveTest(pkg->bindKeys(n,d)),os::shared_type));

		pkg->setKeySize(size::public2048);
		findKeysRaw(n,d,pkg->algorithm(),pkg->keySize());
		pushTest(os::smart_ptr<singleTest>(new publicKeyFileSaveTest(pkg->bindKeys(n,d)),os::shared_type));
	}

/*------------------------------------------------------------
    EXML File Tests
 ------------------------------------------------------------*/

    //Build an XML tree
    static os::smartXMLNode generateReferenceTree()
    {
        os::smartXMLNode ret(new os::XML_Node("testTree"),os::shared_type);
		os::smartXMLNode temp1(new os::XML_Node("cake"),os::shared_type);
		os::smartXMLNode temp2;

		//List of cake
		temp2=os::smartXMLNode(new os::XML_Node("flavor"),os::shared_type);
		temp2->setData("chocolate");
		temp1->addElement(temp2);

		temp2=os::smartXMLNode(new os::XML_Node("gluten"),os::shared_type);
		temp2->setData("yes");
		temp1->addElement(temp2);

		temp2=os::smartXMLNode(new os::XML_Node("dairy"),os::shared_type);
		temp2->setData("yes");
		temp1->addElement(temp2);
		ret->addElement(temp1);

		//List of pancake
		temp1=os::smartXMLNode(new os::XML_Node("pancake"),os::shared_type);
        temp2=os::smartXMLNode(new os::XML_Node("authors"),os::shared_type);
        temp2->getDataList().push_back("Jonathan Bedard");
        temp2->getDataList().push_back("Tom Ostrander");
        temp1->addElement(temp2);

		temp2=os::smartXMLNode(new os::XML_Node("buttermilk"),os::shared_type);
		temp2->setData("yes");
		temp1->addElement(temp2);

		temp2=os::smartXMLNode(new os::XML_Node("gluten"),os::shared_type);
		temp2->setData("no");
		temp1->addElement(temp2);

		temp2=os::smartXMLNode(new os::XML_Node("dairy"),os::shared_type);
		temp2->setData("yes");
		temp1->addElement(temp2);
		ret->addElement(temp1);

		return ret;
    }

    //EXML file save, raw password
    exmlFileSaveTest::exmlFileSaveTest(os::smart_ptr<crypto::streamPackageFrame> spf):
        singleTest(spf->streamAlgorithmName()+", "+spf->hashAlgorithmName()+"("+std::to_string((long long unsigned int)spf->hashSize()*8)+"): EXML File")
    {
        streamPackage=spf;
    }
    //Run test
    void exmlFileSaveTest::test() throw(os::smart_ptr<std::exception>)
    {
        std::string locString = "cryptoFileTest.cpp, exmlFileSaveTest::test()";
        
		try
		{
			os::smartXMLNode xmn=generateReferenceTree();
			if(!crypto::EXML_Output("testFile.xml",xmn,"password",streamPackage))
				throw os::smart_ptr<std::exception>(new generalTestException("EXML write failure",locString),os::shared_type);

			os::smartXMLNode xmlParse=crypto::EXML_Input("testFile.xml","password");
			if(!xmlParse)
				throw os::smart_ptr<std::exception>(new generalTestException("EXML read failure",locString),os::shared_type);

			if(!os::xml::compareTrees(xmn,xmlParse))
				throw os::smart_ptr<std::exception>(new generalTestException("Tree comparison failed",locString),os::shared_type);
		}
		catch(os::smart_ptr<std::exception> e)
		{
			os::delete_file("testFile.xml");
			throw e;
		}
		catch(errorPointer e)
		{
			os::delete_file("pubTest.xml");
			throw os::cast<std::exception,crypto::error>(e);
		}
		catch(...)
		{
			os::delete_file("testFile.xml");
			throw os::smart_ptr<std::exception>(new generalTestException("Unknown exception type",locString),os::shared_type); 
		}
		os::delete_file("testFile.xml");
    }

    //EXML file save, public key
    exmlPublicKeySaveTest::exmlPublicKeySaveTest(os::smart_ptr<crypto::publicKey> pbk):
        singleTest(pbk->algorithmName()+" "+std::to_string((long long unsigned int)32*pbk->size())+" bit: EXML File")
    {
        pubkey=pbk;
    }
    //Run test
    void exmlPublicKeySaveTest::test() throw(os::smart_ptr<std::exception>)
    {
        std::string locString = "cryptoFileTest.cpp, exmlFileSaveTest::test()";
        
		try
		{
			os::smartXMLNode xmn=generateReferenceTree();
			if(!crypto::EXML_Output("pubTest.xml",xmn,pubkey))
				throw os::smart_ptr<std::exception>(new generalTestException("EXML write failure",locString),os::shared_type);

			os::smartXMLNode xmlParse=crypto::EXML_Input("pubTest.xml",pubkey);
			if(!xmlParse)
				throw os::smart_ptr<std::exception>(new generalTestException("EXML read failure",locString),os::shared_type);

			if(!os::xml::compareTrees(xmn,xmlParse))
				throw os::smart_ptr<std::exception>(new generalTestException("Tree comparison failed",locString),os::shared_type);
		}
		catch(os::smart_ptr<std::exception> e)
		{
			os::delete_file("pubTest.xml");
			throw e;
		}
		catch(errorPointer e)
		{
			os::delete_file("pubTest.xml");
			throw os::cast<std::exception,crypto::error>(e);
		}
		catch(...)
		{
			os::delete_file("pubTest.xml");
			throw os::smart_ptr<std::exception>(new generalTestException("Unknown exception type",locString),os::shared_type); 
		}
		os::delete_file("pubTest.xml");
    }

	//Public header
	void exlPublicHeader() throw(os::smart_ptr<std::exception>)
	{
		std::string locString = "cryptoFileTest.cpp, binaryPublicHeader()";

		try
		{
			//Write data
			uint32_t *n,*d;
			os::smart_ptr<publicKeyPackageFrame> pkg=publicKeyTypeBank::singleton()->defaultPackage();
			if(!pkg) return;
			pkg=pkg->getCopy();

			pkg->setKeySize(size::public128);
			findKeysRaw(n,d,pkg->algorithm(),pkg->keySize());
			os::smart_ptr<publicKey> kys=pkg->bindKeys(n,d);
			os::smartXMLNode xmn=generateReferenceTree();
			if(!crypto::EXML_Output("pubTest.xml",xmn,kys,file::PUBLIC_UNLOCK))
				throw os::smart_ptr<std::exception>(new generalTestException("EXML write failure",locString),os::shared_type);

			os::smartXMLNode xmlParse1=crypto::EXML_Input("pubTest.xml",kys);
			if(!xmlParse1)
				throw os::smart_ptr<std::exception>(new generalTestException("EXML read failure (unlock with self)",locString),os::shared_type);
			if(!os::xml::compareTrees(xmn,xmlParse1))
				throw os::smart_ptr<std::exception>(new generalTestException("Tree comparison failed",locString),os::shared_type);

			avlKeyBank kybnk;
			os::smart_ptr<nodeGroup> ng=kybnk.addPair("No-G","Me",kys->getN(),kys->algorithm(),kys->size());
			os::smart_ptr<nodeGroup> ntemp;
			os::smartXMLNode xmlParse2=crypto::EXML_Input("pubTest.xml",&kybnk,ntemp);
			if(!xmlParse2)
				throw os::smart_ptr<std::exception>(new generalTestException("EXML read failure (unlock with bank)",locString),os::shared_type);
			if(!os::xml::compareTrees(xmn,xmlParse2))
				throw os::smart_ptr<std::exception>(new generalTestException("Tree comparison failed",locString),os::shared_type);
			if(!ntemp || ntemp->name() != ng->name())
				throw os::smart_ptr<std::exception>(new generalTestException("Failed to confirm author",locString),os::shared_type);
		}
		catch(os::smart_ptr<std::exception> e)
		{
			os::delete_file("pubTest.xml");
			throw e;
		}
		catch(errorPointer e)
		{
			os::delete_file("pubTest.xml");
			throw os::cast<std::exception,crypto::error>(e);
		}
		catch(...)
		{
			os::delete_file("pubTest.xml");
			throw os::smart_ptr<std::exception>(new generalTestException("Unknown exception type",locString),os::shared_type); 
		}
		os::delete_file("pubTest.xml");
	}
	//Public header
	void exmlDoubleLock() throw(os::smart_ptr<std::exception>)
	{
		std::string locString = "cryptoFileTest.cpp, exmlDoubleLock()";

		try
		{
			//Write data
			uint32_t *n,*d;
			os::smart_ptr<publicKeyPackageFrame> pkg=publicKeyTypeBank::singleton()->defaultPackage();
			if(!pkg) return;
			pkg=pkg->getCopy();

			pkg->setKeySize(size::public128);
			findKeysRaw(n,d,pkg->algorithm(),pkg->keySize());
			os::smart_ptr<publicKey> kys=pkg->bindKeys(n,d);
			os::smartXMLNode xmn=generateReferenceTree();
			if(!crypto::EXML_Output("pubTest.xml",xmn,kys,file::DOUBLE_LOCK))
				throw os::smart_ptr<std::exception>(new generalTestException("EXML write failure",locString),os::shared_type);

			os::smartXMLNode xmlParse=crypto::EXML_Input("pubTest.xml",kys);
			if(!xmlParse)
				throw os::smart_ptr<std::exception>(new generalTestException("EXML read failure",locString),os::shared_type);

			if(!os::xml::compareTrees(xmn,xmlParse))
				throw os::smart_ptr<std::exception>(new generalTestException("Tree comparison failed",locString),os::shared_type);
		}
		catch(os::smart_ptr<std::exception> e)
		{
			os::delete_file("pubTest.xml");
			throw e;
		}
		catch(errorPointer e)
		{
			os::delete_file("pubTest.xml");
			throw os::cast<std::exception,crypto::error>(e);
		}
		catch(...)
		{
			os::delete_file("pubTest.xml");
			throw os::smart_ptr<std::exception>(new generalTestException("Unknown exception type",locString),os::shared_type); 
		}
		os::delete_file("pubTest.xml");
	}

/*------------------------------------------------------------
    EXML File Test Driver
 ------------------------------------------------------------*/

    cryptoEXMLTestSuite::cryptoEXMLTestSuite():
        testSuite("EXML Saving")
    {
        pushTestPackage(streamPackageTypeBank::singleton()->findStream(algo::streamRC4,algo::hashRC4));
        pushTestPackage(publicKeyTypeBank::singleton()->findPublicKey(crypto::algo::publicRSA));
		pushTest("Public Signing",&exlPublicHeader);
		pushTest("Double Lock",&exmlDoubleLock);
    }
    //Attempt to push packages to test
    void cryptoEXMLTestSuite::pushTestPackage(os::smart_ptr<streamPackageFrame> spf)
    {
        if(!spf) return;
        os::smart_ptr<streamPackageFrame> sp=spf->getCopy();
        sp->setHashSize(size::hash64);
        pushTest(os::smart_ptr<singleTest>(new exmlFileSaveTest(sp),os::shared_type));
    
        sp=spf->getCopy();
        sp->setHashSize(size::hash128);
        pushTest(os::smart_ptr<singleTest>(new exmlFileSaveTest(sp),os::shared_type));
    
        sp=spf->getCopy();
        sp->setHashSize(size::hash256);
        pushTest(os::smart_ptr<singleTest>(new exmlFileSaveTest(sp),os::shared_type));
    
        sp=spf->getCopy();
        sp->setHashSize(size::hash512);
        pushTest(os::smart_ptr<singleTest>(new exmlFileSaveTest(sp),os::shared_type));
    }
    //Attempt to push a package to test by public ID
    void cryptoEXMLTestSuite::pushTestPackage(os::smart_ptr<publicKeyPackageFrame> pkg)
    {
        uint32_t *n,*d;
        if(!pkg) return;
        pkg=pkg->getCopy();
    
		pkg->setKeySize(size::public128);
        findKeysRaw(n,d,pkg->algorithm(),pkg->keySize());
        pushTest(os::smart_ptr<singleTest>(new exmlPublicKeySaveTest(pkg->bindKeys(n,d)),os::shared_type));

        pkg->setKeySize(size::public256);
        findKeysRaw(n,d,pkg->algorithm(),pkg->keySize());
        pushTest(os::smart_ptr<singleTest>(new exmlPublicKeySaveTest(pkg->bindKeys(n,d)),os::shared_type));
    
        pkg->setKeySize(size::public512);
        findKeysRaw(n,d,pkg->algorithm(),pkg->keySize());
        pushTest(os::smart_ptr<singleTest>(new exmlPublicKeySaveTest(pkg->bindKeys(n,d)),os::shared_type));
    
        pkg->setKeySize(size::public1024);
        findKeysRaw(n,d,pkg->algorithm(),pkg->keySize());
        pushTest(os::smart_ptr<singleTest>(new exmlPublicKeySaveTest(pkg->bindKeys(n,d)),os::shared_type));
    
        pkg->setKeySize(size::public2048);
        findKeysRaw(n,d,pkg->algorithm(),pkg->keySize());
        pushTest(os::smart_ptr<singleTest>(new exmlPublicKeySaveTest(pkg->bindKeys(n,d)),os::shared_type));
    }

#endif

///@endcond

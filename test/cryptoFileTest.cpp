//Primary author: Jonathan Bedard
//Certified working 1/24/2016

#ifndef CRYPTO_FILE_TEST_CPP
#define CRYPTO_FILE_TEST_CPP

#include <string>
#include <stdint.h>
#include "cryptoFileTest.h"
#include "publicKeyPackage.h"
#include "testKeyGeneration.h"

using namespace crypto;
using namespace test;

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
		singleTest(spf->streamAlgorithmName()+", "+spf->hashAlgorithmName()+"("+std::to_string(spf->hashSize()*8)+"): Binary File")
	{
		streamPackage=spf;
	}
	void binaryFileSaveTest::test() throw(os::smart_ptr<std::exception>)
	{
		std::string locString = "cryptoFileTest.cpp, binaryFileSaveTest::test()";

		//Bind data
		unsigned char refData[100];
		unsigned char readData[100];
		for(int i=0;i<100;i++)
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
			for(int i=0;i<100;i++)
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
		singleTest(pk->algorithmName()+" "+std::to_string(32*pk->size())+" bit: Binary File")
	{
		pubkey=pk;
	}
	void publicKeyFileSaveTest::test() throw(os::smart_ptr<std::exception>)
	{
		std::string locString = "cryptoFileTest.cpp, binaryFileSaveTest::test()";

		//Bind data
		unsigned char refData[100];
		unsigned char readData[100];
		for(int i=0;i<100;i++)
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
			for(int i=0;i<100;i++)
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

#endif

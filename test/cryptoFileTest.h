//Primary author: Jonathan Bedard
//Certified working 1/16/2016

#ifndef CRYPTO_FILE_TEST_H
#define CRYPTO_FILE_TEST_H

#include "streamPackage.h"
#include "binaryEncryption.h"
#include "XMLEncryption.h"
#include "UnitTest.h"

namespace test {

	//Tests binary file saving
	class binaryFileSaveTest:public singleTest
	{
		os::smart_ptr<crypto::streamPackageFrame> streamPackage;
	public:
		binaryFileSaveTest(os::smart_ptr<crypto::streamPackageFrame> spf);
		virtual ~binaryFileSaveTest(){}

		virtual void test() throw(os::smart_ptr<std::exception>);
	};

	//Crypto File Test
	class cryptoFileTestSuite:public testSuite
	{
	public:
		cryptoFileTestSuite();
		virtual ~cryptoFileTestSuite(){}

		void pushTestPackage(os::smart_ptr<crypto::streamPackageFrame> spf);
	};
}

#endif

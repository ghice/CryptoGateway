//Primary author: Jonathan Bedard
//Confirmed working: 1/9/2016

#ifndef CRYPTO_TEST_CPP
#define CRYPTO_TEST_CPP

#include "cryptoTest.h"
#include "c_cryptoTesting.h"
#include "hashTest.h"
#include "streamTest.h"

using namespace test;

/*================================================================
	CryptoGatewayLibraryTest
 ================================================================*/

    //Constructor
    CryptoGatewayLibraryTest::CryptoGatewayLibraryTest():
        libraryTests("CryptoGateway")
    {
        pushSuite(os::smart_ptr<testSuite>(new C_BaseTenSuite(),os::shared_type));
        pushSuite(os::smart_ptr<testSuite>(new BasicNumberTest(),os::shared_type));
        pushSuite(os::smart_ptr<testSuite>(new IntegerTest(),os::shared_type));
        pushSuite(os::smart_ptr<testSuite>(new xorTestSuite(),os::shared_type));
		pushSuite(os::smart_ptr<testSuite>(new rc4TestSuite(),os::shared_type));
		pushSuite(os::smart_ptr<testSuite>(new RC4TestSuite(),os::shared_type));
    }

#endif
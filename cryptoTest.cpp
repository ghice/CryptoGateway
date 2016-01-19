//Primary author: Jonathan Bedard
//Confirmed working: 1/19/2016

#ifndef CRYPTO_TEST_CPP
#define CRYPTO_TEST_CPP

#include "cryptoTest.h"
#include "c_cryptoTesting.h"
#include "hashTest.h"
#include "streamTest.h"
#include "cryptoFileTest.h"
#include "publicKeyTest.h"

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
		pushSuite(os::smart_ptr<testSuite>(new RC4HashTestSuite(),os::shared_type));
		pushSuite(os::smart_ptr<testSuite>(new RC4StreamTestSuite(),os::shared_type));
		pushSuite(os::smart_ptr<testSuite>(new cryptoFileTestSuite(),os::shared_type));
        pushSuite(os::smart_ptr<testSuite>(new RSASuite(),os::shared_type));
    }

#endif
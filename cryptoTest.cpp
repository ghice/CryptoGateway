//Primary author: Jonathan Bedard
//Confirmed working: 11/28/2015

#ifndef CRYPTO_TEST_CPP
#define CRYPTO_TEST_CPP

#include "cryptoTest.h"
#include "c_cryptoTesting.h"

using namespace test;

/*================================================================
	CryptoGatewayLibraryTest
 ================================================================*/

    //Constructor
    CryptoGatewayLibraryTest::CryptoGatewayLibraryTest():
        libraryTests("CryptoGateway")
    {
        pushSuite(os::smart_ptr<testSuite>(new C_BaseTenSuite(),os::shared_type));
    }

#endif
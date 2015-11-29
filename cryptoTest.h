//Primary author: Jonathan Bedard
//Confirmed working: 11/28/2015

#ifndef CRYPTO_TEST_H
#define CRYPTO_TEST_H

#include "CryptoGateway.h"
#include "UnitTest.h"

namespace test
{
    //CryptoGateway Library Test
    class CryptoGatewayLibraryTest: public libraryTests
    {
    public:
        CryptoGatewayLibraryTest();
        virtual ~CryptoGatewayLibraryTest(){}
    };
}

#endif
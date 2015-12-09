//Primary author: Jonathan Bedard
//Confirmed working: 12/9/2015

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
    
    //Crypto Number tests
    class BasicNumberTest: public testSuite
    {
    public:
        BasicNumberTest();
        virtual ~BasicNumberTest(){}
    };
    class IntegerTest: public testSuite
    {
    public:
        IntegerTest();
        virtual ~IntegerTest(){}
    };
}

#endif
/**
 * @file   test/cryptoTest.h
 * @author Jonathan Bedard
 * @date   2/12/2016
 * @brief  CryptoGateway library test header
 * @bug No known bugs.
 *
 * Contains declarations need to bind
 * the CryptoGateway test library to
 * the unit test driver.
 *
 */

///@cond INTERNAL

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

///@endcond
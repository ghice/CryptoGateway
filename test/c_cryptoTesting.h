/**
 * @file   test/cryptoTest.h
 * @author Jonathan Bedard
 * @date   2/6/2016
 * @brief  CryptoGateway library test header
 * @bug No known bugs.
 *
 * Contains declarations need to bind
 * the CryptoGateway test library to
 * the unit test driver.
 *
 */

///@cond INTERNAL

#ifndef C_CRYPTO_TESTING_H
#define C_CRYPTO_TESTING_H

#include "CryptoGateway.h"
#include "UnitTest.h"
#include "cryptoCHeaders.h"

namespace test
{
    //Base-10 C Test Suite
    class C_BaseTenSuite: public testSuite
    {
    public:
        C_BaseTenSuite();
        virtual ~C_BaseTenSuite(){}
    };
}

#endif

///@endcond
/**
 * @file   test/c_cryptoTesting.h
 * @author Jonathan Bedard
 * @date   7/9/2016
 * @brief  Header for C file testing
 * @bug No known bugs.
 *
 * This header is meant for the test
 * suites which are testing raw C code.
 * This header currently contains the
 * Base-Ten suite.
 *
 */

///@cond INTERNAL

#ifndef C_CRYPTO_TESTING_H
#define C_CRYPTO_TESTING_H

#include "UnitTest/UnitTest.h"
#include "CryptoGateway.h"
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
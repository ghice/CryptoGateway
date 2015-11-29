//Primary author: Jonathan Bedard
//Confirmed working: 11/28/2015

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
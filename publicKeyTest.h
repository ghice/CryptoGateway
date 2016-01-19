//Primary author: Jonathan Bedard
//Confirmed working: 1/19/2015

#ifndef PUBLIC_KEY_TEST_H
#define PUBLIC_KEY_TEST_H

#include "cryptoPublicKey.h"
#include "UnitTest.h"

namespace test
{
    //Basic saving and loading for public keys
    template <class pkType>
    class generationTest: public singleTest
    {
    public:
        generationTest():singleTest("Generation"){}
        virtual ~generationTest(){}
    };
    
    //General public key Test suite
    template <class pkType, class pkNumber>
    class publicKeySuite:public testSuite
    {
    public:
        publicKeySuite(std::string pkName):testSuite(pkName+": Public Key")
        {
            pushTest(os::smart_ptr<singleTest>(new generationTest<pkType>(),os::shared_type));
        }
        virtual ~publicKeySuite(){}
    };
    //Public key test suite
    class RSASuite:public publicKeySuite<crypto::publicRSA,crypto::integer>
    {
    public:
        RSASuite():publicKeySuite<crypto::publicRSA,crypto::integer>("RSA")
        {}
        virtual ~RSASuite(){}
    };
}

#endif
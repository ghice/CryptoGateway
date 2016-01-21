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
		void test() throw(os::smart_ptr<std::exception>)
        {
			std::string locString = "publicKeyTest.h, generationTest::test()";

			pkType writeKey(crypto::size::public256);
			while(!writeKey.getN()) os::sleep(50);
			writeKey.setFileName("keytest.dmp");
			writeKey.saveFile();

			pkType readKey("keytest.dmp");

			if(readKey.size()!=writeKey.size())
				throw os::smart_ptr<std::exception>(new generalTestException("Read sizes do no match",locString),os::shared_type);
			if(readKey.algorithm()!=writeKey.algorithm())
				throw os::smart_ptr<std::exception>(new generalTestException("Algorithms do no match",locString),os::shared_type);

			if(!readKey.getN())
				throw os::smart_ptr<std::exception>(new generalTestException("NULL n value",locString),os::shared_type);
			if(readKey!=writeKey)
				throw os::smart_ptr<std::exception>(new generalTestException("Failed to read key",locString),os::shared_type);
		}
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
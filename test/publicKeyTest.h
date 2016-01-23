//Primary author: Jonathan Bedard
//Confirmed working: 1/23/2015

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

			try
			{
				pkType writeKey(crypto::size::public256);
				while(!writeKey.getN()) os::sleep(50);
				if(writeKey.generating())
					throw os::smart_ptr<std::exception>(new generalTestException("Write key says its generating",locString),os::shared_type);
				writeKey.generateNewKeys();
				while(writeKey.generating()) os::sleep(50);
            
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
                
				if(readKey.history()!=writeKey.history())
					throw os::smart_ptr<std::exception>(new generalTestException("History size failed to match!",locString),os::shared_type);
            
				os::smart_ptr<crypto::number> wnum=writeKey.getOldN();
				os::smart_ptr<crypto::number> rnum=readKey.getOldN();
            
				if(!wnum)
					throw os::smart_ptr<std::exception>(new generalTestException("No old n in write key",locString),os::shared_type);
				if(!rnum)
					throw os::smart_ptr<std::exception>(new generalTestException("No old n in read key",locString),os::shared_type);
				if((*wnum) != (*rnum))
					throw os::smart_ptr<std::exception>(new generalTestException("Old \'n\' values do not match",locString),os::shared_type);
				if((*readKey.getN()) == (*rnum))
					throw os::smart_ptr<std::exception>(new generalTestException("Old and new n values match",locString),os::shared_type);
			}
			catch(os::smart_ptr<std::exception> e)
			{
				if(os::check_exists("keytest.dmp"))
					os::delete_file("keytest.dmp");
				throw e;
			}
			catch(...)
			{
				if(os::check_exists("keytest.dmp"))
					os::delete_file("keytest.dmp");
				throw os::smart_ptr<std::exception>(new unknownException(locString),os::shared_type);
			}
			if(os::check_exists("keytest.dmp")) os::delete_file("keytest.dmp");
		}
    };
    
    //Simple key test
    template <class pkType>
    class basicPublicKeyTest:public singleTest
    {
        uint16_t publicLen;
    public:
        basicPublicKeyTest(uint16_t pl):singleTest("Basic Test: "+std::to_string(pl*32)){publicLen=pl;}
        virtual ~basicPublicKeyTest(){}
        
        void test() throw(os::smart_ptr<std::exception>)
        {
        }
    };
    
    
    //General public key Test suite
    template <class pkType>
    class publicKeySuite:public testSuite
    {
    public:
        publicKeySuite(std::string pkName):testSuite(pkName+": Public Key")
        {
            pushTest(os::smart_ptr<singleTest>(new generationTest<pkType>(),os::shared_type));
            
            pushTest(os::smart_ptr<singleTest>(new basicPublicKeyTest<pkType>(crypto::size::public256),os::shared_type));
            pushTest(os::smart_ptr<singleTest>(new basicPublicKeyTest<pkType>(crypto::size::public512),os::shared_type));
            pushTest(os::smart_ptr<singleTest>(new basicPublicKeyTest<pkType>(crypto::size::public1024),os::shared_type));
            pushTest(os::smart_ptr<singleTest>(new basicPublicKeyTest<pkType>(crypto::size::public2048),os::shared_type));
        }
        virtual ~publicKeySuite(){}
    };
    //Public key test suite
    class RSASuite:public publicKeySuite<crypto::publicRSA>
    {
    public:
        RSASuite():publicKeySuite<crypto::publicRSA>("RSA")
        {}
        virtual ~RSASuite(){}
    };
}

#endif
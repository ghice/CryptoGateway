//Primary author: Jonathan Bedard
//Certified working 12/18/2015

#ifndef HASH_TEST_H
#define HASH_TEST_H

#include "UnitTest.h"
#include "cryptoHash.h"

namespace test {
    
    //Hash test frame
    template <class hashClass>
    class hashTest:public singleTest
    {
    protected:
        std::string _hashName;
        uint16_t _hashSize;
    public:
        hashTest(std::string tn,std::string hashName, uint16_t hashSize):
            singleTest(tn+": "+hashName+" "+std::to_string(hashSize*8)+" bit")
        {
            _hashName=hashName;
            _hashSize=hashSize;
        }
        virtual ~hashTest(){}
    };
    
    //Sets a random hash value (for testing misc hash functionality)
    template <class hashClass>
    hashClass randomHash(uint16_t hashType)
    {
        unsigned char data[1024];
        
        for(int i=0;i<1024;i++)
            data[i]=(unsigned char)rand();
        
        return crypto::hashData<hashClass>(hashType,data,512);
    }
    
    //Constructor test
    template <class hashClass>
    class hashConstructorTest:public hashTest<hashClass>
    {
    public:
        hashConstructorTest(std::string tn,std::string hashName, uint16_t hashSize):
            hashTest<hashClass>(tn,hashName,hashSize){}
        virtual ~hashConstructorTest(){}
        
        virtual void test() throw(os::smart_ptr<std::exception>)
        {
            std::string locString = "hashTest.h, hashConstructorTest::test()";
            
            //Attempts the random hash 20 times
            for(int i=0;i<20;i++)
            {
                hashClass hsh1=randomHash<hashClass>(hashTest<hashClass>::_hashSize);
                hashClass hsh2(hsh1);
                hashClass hsh3=hsh1;
            
                //Copy constructor
                if(hsh1!=hsh2)
                    throw os::smart_ptr<std::exception>(new generalTestException("Copy constructor failed",locString),os::shared_type);
                if(hsh1!=hsh3)
                    throw os::smart_ptr<std::exception>(new generalTestException("Equals constructor failed",locString),os::shared_type);
            }
        }
    };
    
    //Compare test
    template <class hashClass>
    class hashCompareTest:public hashTest<hashClass>
    {
    public:
        hashCompareTest(std::string tn,std::string hashName, uint16_t hashSize):
            hashTest<hashClass>(tn,hashName,hashSize){}
        virtual ~hashCompareTest(){}
        
        virtual void test() throw(os::smart_ptr<std::exception>)
        {
            std::string locString = "hashTest.h, hashCompareTest::test()";
            
            
        }
    };
    
    //Equality operator test
    template <class hashClass>
    class hashEqualityOperatorTest:public hashTest<hashClass>
    {
    public:
        hashEqualityOperatorTest(std::string tn,std::string hashName, uint16_t hashSize):
        hashTest<hashClass>(tn,hashName,hashSize){}
        virtual ~hashEqualityOperatorTest(){}
        
        virtual void test() throw(os::smart_ptr<std::exception>)
        {
            std::string locString = "hashTest.h, hashEqualityOperatorTest::test()";
            
            
        }
    };
    
    //Hash test suite
    template <class hashClass>
    class hashSuite:public testSuite
    {
    public:
        hashSuite(std::string hashName):
            testSuite(hashName+" Suite")
        {
            uint16_t hSize;
            for(int i=0;i<4;i++)
            {
                if(i==0) hSize=crypto::size::hash64;
                else if(i==1) hSize=crypto::size::hash128;
                else if(i==2) hSize=crypto::size::hash256;
                else if(i==3) hSize=crypto::size::hash512;
                
                pushTest(os::smart_ptr<singleTest>(new hashConstructorTest<hashClass>("Constructor",hashName,hSize)));
                pushTest(os::smart_ptr<singleTest>(new hashConstructorTest<hashClass>("Compare",hashName,hSize)));
                pushTest(os::smart_ptr<singleTest>(new hashConstructorTest<hashClass>("Equality Operators",hashName,hSize)));
            }
        }
        virtual ~hashSuite(){}
    };
    
    //XOR Hash test
    class xorTestSuite:public hashSuite<crypto::xorHash>
    {
    public:
        xorTestSuite();
        virtual ~xorTestSuite(){}
    };
}

#endif
//Primary author: Jonathan Bedard
//Certified working 12/18/2015

#ifndef HASH_TEST_CPP
#define HASH_TEST_CPP

#include "hashTest.h"

using namespace test;

/*================================================================
	xor Hash
 ================================================================*/

    //Basic xor test
    void basicXORTest() throw(os::smart_ptr<std::exception>)
    {
        std::string locString = "hashTest.cpp, basicXORTest()";
        
        unsigned char val[128];
        memset(val,0,128);
        val[0]=6;
        val[64]=3;
        
        crypto::xorHash h1=crypto::xorHash::hash64Bit(val,128);
        crypto::xorHash h2=crypto::xorHash::hash64Bit(NULL,0);
        h2[0]=5;
        
        if(h1!=h2)
            throw os::smart_ptr<std::exception>(new generalTestException("XOR hash algorithm failed",locString),os::shared_type);
    }
    //xor Test suite
    xorTestSuite::xorTestSuite():
        hashSuite("XOR")
    {
        pushTest("XOR Algorithm",&basicXORTest);
    }

#endif
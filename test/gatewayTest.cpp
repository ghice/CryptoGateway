/**
 * @file   test/gatewayTest.cpp
 * @author Jonathan Bedard
 * @date   2/20/2016
 * @brief  Implementation for end-to-end gateway testing
 * @bug No known bugs.
 *
 * This file contains implementation of the
 * key bank tests and the end-to-end gateway
 * tests.  These tests are not exhaustive,
 * they test basic functionality of both
 * structures.
 *
 */

///@cond INTERNAL

#ifndef GATEWAY_TEST_CPP
#define GATEWAY_TEST_CPP

#include "gatewayTest.h"
#include "testKeyGeneration.h"
#include <string>

using namespace test;
using namespace os;
using namespace crypto;


/*================================================================
	Key Bank Tests
 ================================================================*/

    //Basic key bank test
    void basicBankTest() throw(os::smart_ptr<std::exception>)
    {
        std::string locString = "gatewayTest.cpp, basicBankTest()";
        avlKeyBank cbank("tempout.xml");
        os::smart_ptr<publicRSA> key=getStaticKeys<publicRSA>(size::public512,0);
        cbank.addPair("GroupA","Name1",key->getN(),algo::publicRSA,size::public512);
        cbank.addPair("GroupA","Name2",key->getD(),algo::publicRSA,size::public512);
        
        //Name1 by name
        os::smart_ptr<nodeGroup> found=cbank.find("GroupA","Name1");
        if(!found)
            throw os::smart_ptr<std::exception>(new generalTestException("Failed to find Name1 by name",locString),os::shared_type);
        if(found->name()!="GroupA:Name1")
            throw os::smart_ptr<std::exception>(new generalTestException("Name1's name doesn't match (name)",locString),os::shared_type);
        
        //Name1 by key
        found=cbank.find(key->getN(),algo::publicRSA,size::public512);
        if(!found)
            throw os::smart_ptr<std::exception>(new generalTestException("Failed to find Name1 by key",locString),os::shared_type);
        if(found->name()!="GroupA:Name1")
            throw os::smart_ptr<std::exception>(new generalTestException("Name1's name doesn't match (key)",locString),os::shared_type);
        
        //Name2 by name
        found=cbank.find("GroupA","Name2");
        if(!found)
            throw os::smart_ptr<std::exception>(new generalTestException("Failed to find Name2 by name",locString),os::shared_type);
        if(found->name()!="GroupA:Name2")
            throw os::smart_ptr<std::exception>(new generalTestException("Name2's name doesn't match (name)",locString),os::shared_type);
    }
    //Save/load test
    void bankSaveLoadTest() throw(os::smart_ptr<std::exception>)
    {
        std::string locString = "gatewayTest.cpp, basicBankTest()";
        avlKeyBank cbank("tempout.xml");
        os::smart_ptr<publicRSA> key=getStaticKeys<publicRSA>(size::public512,0);
        cbank.addPair("GroupA","Name1",key->getN(),algo::publicRSA,size::public512);
        cbank.addPair("GroupA","Name2",key->getD(),algo::publicRSA,size::public512);
        cbank.save();
    }

/*================================================================
	Bind Suites
 ================================================================*/

    //Key bank test
    keyBankSuite::keyBankSuite():
        testSuite("Key Bank")
    {
        pushTest("Basics",&basicBankTest);
        pushTest("Save/Load",&bankSaveLoadTest);
    }

#endif

///@endcond
/**
 * @file   test/gatewayTest.cpp
 * @author Jonathan Bedard
 * @date   2/21/2016
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
        avlKeyBank cbank;
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
		std::string locString = "gatewayTest.cpp, bankSaveLoadTest()";
		try
		{
			avlKeyBank cbank("tempout.xml");
			if(cbank.numberErrors()==0)
				throw os::smart_ptr<std::exception>(new generalTestException("Found save file, should not have",locString),os::shared_type);
			cbank.popError();
			os::smart_ptr<publicRSA> key=getStaticKeys<publicRSA>(size::public512,0);
			cbank.addPair("GroupA","Name1",key->getN(),algo::publicRSA,size::public512);
			cbank.addPair("GroupA","Name2",key->getD(),algo::publicRSA,size::public512);
			cbank.save();
			if(cbank.numberErrors()>0)
				throw os::smart_ptr<std::exception>(new generalTestException("Failed to save XML file",locString),os::shared_type);

			//Load
			avlKeyBank newBank("tempout.xml");
			if(newBank.numberErrors()>0)
				throw os::smart_ptr<std::exception>(new generalTestException("Failed to load XML file",locString),os::shared_type);

			 //Name1 by name
			os::smart_ptr<nodeGroup> found=newBank.find("GroupA","Name1");
			if(!found)
				throw os::smart_ptr<std::exception>(new generalTestException("Failed to find Name1 by name",locString),os::shared_type);
			if(found->name()!="GroupA:Name1")
				throw os::smart_ptr<std::exception>(new generalTestException("Name1's name doesn't match (name)",locString),os::shared_type);
        
			//Name1 by key
			found=newBank.find(key->getN(),algo::publicRSA,size::public512);
			if(!found)
				throw os::smart_ptr<std::exception>(new generalTestException("Failed to find Name1 by key",locString),os::shared_type);
			if(found->name()!="GroupA:Name1")
				throw os::smart_ptr<std::exception>(new generalTestException("Name1's name doesn't match (key)",locString),os::shared_type);
        
			//Name2 by name
			found=newBank.find("GroupA","Name2");
			if(!found)
				throw os::smart_ptr<std::exception>(new generalTestException("Failed to find Name2 by name",locString),os::shared_type);
			if(found->name()!="GroupA:Name2")
				throw os::smart_ptr<std::exception>(new generalTestException("Name2's name doesn't match (name)",locString),os::shared_type);
		}
		catch(os::smart_ptr<std::exception> e)
		{
			os::delete_file("tempout.xml");
			throw e;
		}
		catch(...)
		{
			os::delete_file("tempout.xml");
			throw os::smart_ptr<std::exception>(new unknownException(locString),os::shared_type);
		}
		os::delete_file("tempout.xml");
    }
	//Merge test
	void bankMergeTest() throw(os::smart_ptr<std::exception>)
	{
		std::string locString = "gatewayTest.cpp, bankMergeTest()";
        avlKeyBank cbank;
        os::smart_ptr<publicRSA> key1=getStaticKeys<publicRSA>(size::public512,0);
		os::smart_ptr<publicRSA> key2=getStaticKeys<publicRSA>(size::public512,1);

		cbank.addPair("GroupA","Name1",key1->getN(),algo::publicRSA,size::public512);
        cbank.addPair("GroupA","Name2",key1->getD(),algo::publicRSA,size::public512);
		cbank.addPair("GroupA","Name3",key2->getN(),algo::publicRSA,size::public512);
		cbank.addPair("GroupA","Name4",key2->getN(),algo::publicRSA,size::public512);
		cbank.addPair("GroupA","Name2",key2->getD(),algo::publicRSA,size::public512);
		cbank.addPair("GroupA","Name2",key1->getN(),algo::publicRSA,size::public512);

		//Check to see if Name1 and Name2 point to the same group node
		os::smart_ptr<nodeGroup> found1=cbank.find("GroupA","Name1");
		os::smart_ptr<nodeGroup> found2=cbank.find("GroupA","Name2");
		if(found1!=found2)
			throw os::smart_ptr<std::exception>(new generalTestException("Double merge failed",locString),os::shared_type);

		//Name merge check
		found1=cbank.find("GroupA","Name3");
		found2=cbank.find("GroupA","Name4");
		if(found1!=found2)
			throw os::smart_ptr<std::exception>(new generalTestException("Name merge failed",locString),os::shared_type);

		//Key merge check
		found1=cbank.find(key1->getN(),algo::publicRSA,size::public512);
		found2=cbank.find(key2->getD(),algo::publicRSA,size::public512);
		if(found1!=found2)
			throw os::smart_ptr<std::exception>(new generalTestException("Key merge failed",locString),os::shared_type);

		//Ensure some things haven't merged
		found1=cbank.find("GroupA","Name1");
		found2=cbank.find("GroupA","Name3");
		if(found1==found2)
			throw os::smart_ptr<std::exception>(new generalTestException("Too many merges occured",locString),os::shared_type);
	}
	//Timestamp test: name
	void bankNameTimestampTest() throw(os::smart_ptr<std::exception>)
	{
		std::string locString = "gatewayTest.cpp, bankNameTimestampTest()";
        avlKeyBank cbank;
        os::smart_ptr<publicRSA> key=getStaticKeys<publicRSA>(size::public512,0);

		cbank.addPair("GroupA","Name1",key->getN(),algo::publicRSA,size::public512);
		os::sleep(2000);
        cbank.addPair("GroupA","Name2",key->getN(),algo::publicRSA,size::public512);

		//Set up array
		os::smart_ptr<nodeGroup> found=cbank.find("GroupA","Name1");
        if(!found)
            throw os::smart_ptr<std::exception>(new generalTestException("Failed to find node",locString),os::shared_type);
		unsigned int size;
		auto arr=found->namesByTimestamp(size);
		
		//Check array
		if(size!=2)
			throw os::smart_ptr<std::exception>(new generalTestException("Name array size wrong",locString),os::shared_type);
		if(arr[0]->name()!="Name2")
			throw os::smart_ptr<std::exception>(new generalTestException("First node wrong",locString),os::shared_type);
		if(arr[1]->name()!="Name1")
			throw os::smart_ptr<std::exception>(new generalTestException("Second node wrong",locString),os::shared_type);
	}
	//Timestamp test: key
	void bankKeyTimestampTest() throw(os::smart_ptr<std::exception>)
	{
		std::string locString = "gatewayTest.cpp, bankKeyTimestampTest()";
        avlKeyBank cbank;
        os::smart_ptr<publicRSA> key=getStaticKeys<publicRSA>(size::public512,0);

		cbank.addPair("GroupA","Name1",key->getN(),algo::publicRSA,size::public512);
		os::sleep(2000);
        cbank.addPair("GroupA","Name1",key->getD(),algo::publicRSA,size::public512);

		//Set up array
		os::smart_ptr<nodeGroup> found=cbank.find("GroupA","Name1");
        if(!found)
            throw os::smart_ptr<std::exception>(new generalTestException("Failed to find node",locString),os::shared_type);
		unsigned int size;
		auto arr=found->keysByTimestamp(size);

		//Check array
		if(size!=2)
			throw os::smart_ptr<std::exception>(new generalTestException("Key array size wrong",locString),os::shared_type);
		if(*(arr[0]->key())!=*(key->getD()))
			throw os::smart_ptr<std::exception>(new generalTestException("First node wrong",locString),os::shared_type);
		if(*(arr[1]->key())!=*(key->getN()))
			throw os::smart_ptr<std::exception>(new generalTestException("Second node wrong",locString),os::shared_type);
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
		pushTest("Node Merging",&bankMergeTest);
		pushTest("Timestamp: Name",&bankNameTimestampTest);
		pushTest("Timestamp: Key",&bankKeyTimestampTest);
    }

#endif

///@endcond
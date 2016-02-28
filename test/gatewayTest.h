/**
 * @file   test/gatewayTest.h
 * @author Jonathan Bedard
 * @date   2/28/2016
 * @brief  Header for end-to-end gateway testing
 * @bug No known bugs.
 *
 * This header contains declarations of the
 * key bank tests and the end-to-end gateway
 * tests.  These tests are not exhaustive,
 * they test basic functionality of both
 * structures.
 *
 */

///@cond INTERNAL

#ifndef GATEWAY_TEST_H
#define GATEWAY_TEST_H

#include "CryptoGateway.h"
#include "UnitTest.h"

namespace test
{
    //Key-bank test suite
    class keyBankSuite: public testSuite
    {
    public:
        keyBankSuite();
        virtual ~keyBankSuite(){}
    };
	//User test suite
    class userSuite: public testSuite
    {
    public:
        userSuite();
        virtual ~userSuite(){}
    };
}

#endif

///@endcond
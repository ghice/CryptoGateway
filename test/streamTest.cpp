//Primary author: Jonathan Bedard
//Certified working 1/15/2016

#ifndef STREAM_TEST_CPP
#define STREAM_TEST_CPP

#include "streamTest.h"

using namespace test;

/*================================================================
	RC4 Tests
 ================================================================*/

	 //Basic xor test
    void RC4NULLTest() throw(os::smart_ptr<std::exception>)
    {
		std::string locString = "streamTest.cpp, RC4NULLTest()";
		uint8_t val[16];
		uint8_t comp[20];
		memset(val,0,16);
		crypto::RCFour algo(val,16);

		comp[0]=3;		comp[1]=132;	comp[2]=144;	comp[3]=96;
		comp[4]=47;		comp[5]=156;	comp[6]=172;	comp[7]=172;
		comp[8]=155;	comp[9]=212;	comp[10]=127;	comp[11]=63;
		comp[12]=53;	comp[13]=27;	comp[14]=156;	comp[15]=173;
		comp[16]=94;	comp[17]=62;	comp[18]=73;	comp[19]=183;


		for(int i=0;i<20;i++)
		{
			//testout<<(int)algo.getNext()<<std::endl;
			if(comp[i]!=algo.getNext())
				throw os::smart_ptr<std::exception>(new generalTestException("Failed to match element "+std::to_string(i),locString),os::shared_type);
		}
	}
	//RC4 Tests
	RC4StreamTestSuite::RC4StreamTestSuite():
		streamTestSuite<crypto::RCFour>("RC-4",crypto::algo::streamRC4)
	{
		pushTest("RC-4 Algorithm",&RC4NULLTest);
	}

#endif
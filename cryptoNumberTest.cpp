//Primary author: Jonathan Bedard
//Confirmed working: 12/8/2015

#ifndef CRYPTO_NUMBER_TEST_CPP
#define CRYPTO_NUMBER_TEST_CPP

#include "cryptoTest.h"
#include "cryptoNumber.h"

using namespace test;
using namespace os;
using namespace crypto;

	//Tests number constructor
    void numberConstructorsTest() throw(os::smart_ptr<std::exception>)
    {
        std::string locString = "cryptoNumberTest.cpp, numberConstructorsTest()";

		//Basic
		number num;
		if(num.numberDefinition()==NULL)
			throw os::smart_ptr<std::exception>(new generalTestException("NULL Number definition: basic",locString),shared_type);
		if(num.typeID()!=crypto::numberType::Default)
			throw os::smart_ptr<std::exception>(new generalTestException("Unexpected number type: basic",locString),shared_type);
		if(num.name()!=std::string(crypto::numberName::Default))
			throw os::smart_ptr<std::exception>(new generalTestException("Unexpected number name: basic",locString),shared_type);
		if(num.size()!=1)
			throw os::smart_ptr<std::exception>(new generalTestException("Unexpected number size: basic",locString),shared_type);
		if(num.data()[0]!=0)
			throw os::smart_ptr<std::exception>(new generalTestException("Unexpected number: basic",locString),shared_type);

		//Size constructor
		number num2(4);
		if(num2.numberDefinition()==NULL)
			throw os::smart_ptr<std::exception>(new generalTestException("NULL Number definition: size",locString),shared_type);
		if(num2.typeID()!=crypto::numberType::Default)
			throw os::smart_ptr<std::exception>(new generalTestException("Unexpected number type: size",locString),shared_type);
		if(num2.name()!=std::string(crypto::numberName::Default))
			throw os::smart_ptr<std::exception>(new generalTestException("Unexpected number name: size",locString),shared_type);
		if(num2.size()!=4)
			throw os::smart_ptr<std::exception>(new generalTestException("Unexpected number size: size",locString),shared_type);
		if(num2.data()[3]!=0 || num2.data()[2]!=0 || num2.data()[1]!=0 || num2.data()[0]!=0)
			throw os::smart_ptr<std::exception>(new generalTestException("Unexpected number: size",locString),shared_type);

		//Data constructor
		uint32_t a[3];
		a[2]=2;	a[1]=1;	a[0]=0;
		number num3(a,3);
		if(num3.numberDefinition()==NULL)
			throw os::smart_ptr<std::exception>(new generalTestException("NULL Number definition: data",locString),shared_type);
		if(num3.typeID()!=crypto::numberType::Default)
			throw os::smart_ptr<std::exception>(new generalTestException("Unexpected number type: data",locString),shared_type);
		if(num3.name()!=std::string(crypto::numberName::Default))
			throw os::smart_ptr<std::exception>(new generalTestException("Unexpected number name: data",locString),shared_type);
		if(num3.size()!=3)
			throw os::smart_ptr<std::exception>(new generalTestException("Unexpected number size: data",locString),shared_type);
		if(num3.data()[2]!=2 || num3.data()[1]!=1 || num3.data()[0]!=0)
			throw os::smart_ptr<std::exception>(new generalTestException("Unexpected number: data",locString),shared_type);

		//Copy constructor
		number num4(num3);
		if(num4.numberDefinition()==NULL)
			throw os::smart_ptr<std::exception>(new generalTestException("NULL Number definition: copy",locString),shared_type);
		if(num4.typeID()!=crypto::numberType::Default)
			throw os::smart_ptr<std::exception>(new generalTestException("Unexpected number type: copy",locString),shared_type);
		if(num4.name()!=std::string(crypto::numberName::Default))
			throw os::smart_ptr<std::exception>(new generalTestException("Unexpected number name: copy",locString),shared_type);
		if(num4.size()!=3)
			throw os::smart_ptr<std::exception>(new generalTestException("Unexpected number size: copy",locString),shared_type);
		if(num4.data()[2]!=2 || num4.data()[1]!=1 || num4.data()[0]!=0)
			throw os::smart_ptr<std::exception>(new generalTestException("Unexpected number: copy",locString),shared_type);

		//Equal constructor
		number num5=num4;
		if(num5.numberDefinition()==NULL)
			throw os::smart_ptr<std::exception>(new generalTestException("NULL Number definition: equal",locString),shared_type);
		if(num5.typeID()!=crypto::numberType::Default)
			throw os::smart_ptr<std::exception>(new generalTestException("Unexpected number type: equal",locString),shared_type);
		if(num5.name()!=std::string(crypto::numberName::Default))
			throw os::smart_ptr<std::exception>(new generalTestException("Unexpected number name: equal",locString),shared_type);
		if(num5.size()!=3)
			throw os::smart_ptr<std::exception>(new generalTestException("Unexpected number size: equal",locString),shared_type);
		if(num5.data()[2]!=2 || num5.data()[1]!=1 || num5.data()[0]!=0)
			throw os::smart_ptr<std::exception>(new generalTestException("Unexpected number: equal",locString),shared_type);
	}
	//Comparison
	void numberComparisonTest() throw(os::smart_ptr<std::exception>)
	{
		std::string locString = "cryptoNumberTest.cpp, numberComparisonTest()";

		//Raw comparisons
		uint32_t tone,ttwo;
		tone=1;	ttwo=2;
		number num1, num2;
		
		//==
		num1=number(&tone,1);	num2=number(&tone,1);
		if(!(num1==num2)) throw os::smart_ptr<std::exception>(new generalTestException("1==1 failed",locString),shared_type);
		num1=number(&tone,1);	num2=number(&ttwo,1);
		if(num1==num2) throw os::smart_ptr<std::exception>(new generalTestException("1==2 succeeded",locString),shared_type);

		//!=
		num1=number(&tone,1);	num2=number(&tone,1);
		if(num1!=num2) throw os::smart_ptr<std::exception>(new generalTestException("1!=1 succeeded",locString),shared_type);
		num1=number(&tone,1);	num2=number(&ttwo,1);
		if(!(num1!=num2)) throw os::smart_ptr<std::exception>(new generalTestException("1!=2 failed",locString),shared_type);

		//>=
		num1=number(&tone,1);	num2=number(&tone,1);
		if(!(num1>=num2)) throw os::smart_ptr<std::exception>(new generalTestException("1>=1 failed",locString),shared_type);
		num1=number(&tone,1);	num2=number(&ttwo,1);
		if(num1>=num2) throw os::smart_ptr<std::exception>(new generalTestException("1>=2 succeeded",locString),shared_type);

		//<=
		num1=number(&ttwo,1);	num2=number(&tone,1);
		if(num1<=num2) throw os::smart_ptr<std::exception>(new generalTestException("1<=1 succeeded",locString),shared_type);
		num1=number(&tone,1);	num2=number(&ttwo,1);
		if(!(num1<=num2)) throw os::smart_ptr<std::exception>(new generalTestException("1<=2 failed",locString),shared_type);

		//>
		num1=number(&ttwo,1);	num2=number(&tone,1);
		if(!(num1>num2)) throw os::smart_ptr<std::exception>(new generalTestException("2>1 failed",locString),shared_type);
		num1=number(&tone,1);	num2=number(&ttwo,1);
		if(num1>num2) throw os::smart_ptr<std::exception>(new generalTestException("1>2 succeeded",locString),shared_type);

		//<
		num1=number(&ttwo,1);	num2=number(&tone,1);
		if(num1<num2) throw os::smart_ptr<std::exception>(new generalTestException("1<1 succeeded",locString),shared_type);
		num1=number(&tone,1);	num2=number(&ttwo,1);
		if(!(num1<num2)) throw os::smart_ptr<std::exception>(new generalTestException("1<2 failed",locString),shared_type);

		//Double length tests
		uint32_t arr[2];	arr[1]=2;	arr[0]=1;
		number big(arr,2);

		//2:1 != 1
		if(big == num2) throw os::smart_ptr<std::exception>(new generalTestException("2:1 == 1 succeeded",locString),shared_type);

		//2:1 > 1
		if(big <= num2) throw os::smart_ptr<std::exception>(new generalTestException("2:1 <= 1 succeeded",locString),shared_type);

		//1 < 2:1
		if(num2 >= big) throw os::smart_ptr<std::exception>(new generalTestException("1 >= 2:1 succeeded",locString),shared_type);
	}

/*================================================================
	C Test Suites
 ================================================================*/

    //Basic number test
    BasicNumberTest::BasicNumberTest():
        testSuite("Basic Number")
    {
        pushTest("Constructor",&numberConstructorsTest);
		pushTest("Comparison",&numberComparisonTest);
    }
    //Base-10 number
    Base10NumberTest::Base10NumberTest():
        testSuite("Base 10 Number")
    {
        
    }

#endif
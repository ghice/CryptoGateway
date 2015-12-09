//Primary author: Jonathan Bedard
//Confirmed working: 12/9/2015

#ifndef CRYPTO_NUMBER_TEST_CPP
#define CRYPTO_NUMBER_TEST_CPP

#include "cryptoTest.h"
#include "cryptoNumber.h"

using namespace test;
using namespace os;
using namespace crypto;

/*================================================================
	Number Tests
 ================================================================*/

    //Number type test
    void numberTypeTest() throw(os::smart_ptr<std::exception>)
    {
        std::string locString = "cryptoNumberTest.cpp, numberTypeTest()";
        
        number num;
        
        //Check all types
        if(num.hasCompare())
            throw os::smart_ptr<std::exception>(new generalTestException("hasCompare failed",locString),shared_type);
        if(num.hasAddition())
            throw os::smart_ptr<std::exception>(new generalTestException("hasAddition failed",locString),shared_type);
        if(num.hasSubtraction())
            throw os::smart_ptr<std::exception>(new generalTestException("hasSubtraction failed",locString),shared_type);
        if(num.hasRightShift())
            throw os::smart_ptr<std::exception>(new generalTestException("hasRightShift failed",locString),shared_type);
        if(num.hasLeftShift())
            throw os::smart_ptr<std::exception>(new generalTestException("hasLeftShift failed",locString),shared_type);
        if(num.hasMultiplication())
            throw os::smart_ptr<std::exception>(new generalTestException("hasMultiplication failed",locString),shared_type);
        if(num.hasDivision())
            throw os::smart_ptr<std::exception>(new generalTestException("hasDivision failed",locString),shared_type);
        if(num.hasModulo())
            throw os::smart_ptr<std::exception>(new generalTestException("hasModulo failed",locString),shared_type);
        if(num.hasExponentiation())
            throw os::smart_ptr<std::exception>(new generalTestException("hasExponentiation failed",locString),shared_type);
        if(num.hasModuloExponentiation())
            throw os::smart_ptr<std::exception>(new generalTestException("hasModuloExponentiation failed",locString),shared_type);
        if(num.hasGCD())
            throw os::smart_ptr<std::exception>(new generalTestException("hasGCD failed",locString),shared_type);
        if(num.hasModInverse())
            throw os::smart_ptr<std::exception>(new generalTestException("hasModInverse failed",locString),shared_type);
    }
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
    //Array access
    void numberArrayAccessTest() throw(os::smart_ptr<std::exception>)
    {
        std::string locString = "cryptoNumberTest.cpp, numberArrayAccessTest()";
        uint32_t arr[2];
        arr[1]=3;   arr[0]=5;
        number num(arr,2);
        
        //Test positions
        if(num[0]!=5 && num[1]!=3)
            throw os::smart_ptr<std::exception>(new generalTestException("Read access failed!",locString),shared_type);
        
        //Overflow
        if(num[2]!=0)
            throw os::smart_ptr<std::exception>(new generalTestException("Overflow failed!",locString),shared_type);
        
        //Write access
        num[0]=3;
        num[1]=16;
        if(num[0]!=3 && num[1]!=16)
            throw os::smart_ptr<std::exception>(new generalTestException("Write access failed!",locString),shared_type);
    }
    //To string
    void numberToStringTest() throw(os::smart_ptr<std::exception>)
    {
        std::string locString = "cryptoNumberTest.cpp, numberToStringTest()";
        number num(4);
        
        //All zeros
        if(num.toString()!="00000000:00000000:00000000:00000000")
            throw os::smart_ptr<std::exception>(new generalTestException("Zero case failure",locString),shared_type);
        
        //1, 2, 3, 4
        num[0]=1;
        num[1]=2;
        num[2]=3;
        num[3]=4;
        if(num.toString()!="00000004:00000003:00000002:00000001")
            throw os::smart_ptr<std::exception>(new generalTestException("1, 2, 3, 4 case failure",locString),shared_type);
        
        //5, 6, 7, 8
        num[0]=5;
        num[1]=6;
        num[2]=7;
        num[3]=8;
        if(num.toString()!="00000008:00000007:00000006:00000005")
        throw os::smart_ptr<std::exception>(new generalTestException("5, 6, 7, 8 case failure",locString),shared_type);
        
        //9, A, B, C
        num[0]=9;
        num[1]=10;
        num[2]=11;
        num[3]=12;
        if(num.toString()!="0000000C:0000000B:0000000A:00000009")
        throw os::smart_ptr<std::exception>(new generalTestException("9, A, B, C case failure",locString),shared_type);
        
        //D, E, F, 10
        num[0]=13;
        num[1]=14;
        num[2]=15;
        num[3]=16;
        if(num.toString()!="00000010:0000000F:0000000E:0000000D")
        throw os::smart_ptr<std::exception>(new generalTestException("D, E, F, 10 case failure",locString),shared_type);
        
        //11, 12, 13, 14
        num[0]=17;
        num[1]=18;
        num[2]=19;
        num[3]=20;
        if(num.toString()!="00000014:00000013:00000012:00000011")
        throw os::smart_ptr<std::exception>(new generalTestException("11, 12, 13, 14 case failure",locString),shared_type);
    }
    //From string
    void numberFromStringTest() throw(os::smart_ptr<std::exception>)
    {
        std::string locString = "cryptoNumberTest.cpp, numberFromStringTest()";
        number comp(4);
        number misc;
        
        //Build 0
        misc.fromString("0");
        if(comp!=misc)
            throw os::smart_ptr<std::exception>(new generalTestException("Zero build failure",locString),shared_type);
        
        //Build 1
        comp[0]=1;
        misc.fromString("1");
        if(comp!=misc)
            throw os::smart_ptr<std::exception>(new generalTestException("One build failure",locString),shared_type);
        
        //4:3:2:1
        comp[3]=4;
        comp[2]=3;
        comp[1]=2;
        comp[0]=1;
        misc.fromString("4:3:2:1");
        if(comp!=misc)
            throw os::smart_ptr<std::exception>(new generalTestException("4:3:2:1 build failure",locString),shared_type);
        
        //8:7:6:5
        comp[3]=8;
        comp[2]=7;
        comp[1]=6;
        comp[0]=5;
        misc.fromString("8:7:6:5");
        if(comp!=misc)
        throw os::smart_ptr<std::exception>(new generalTestException("8:7:6:5 build failure",locString),shared_type);
        
        //C:B:A:9
        comp[3]=12;
        comp[2]=11;
        comp[1]=10;
        comp[0]=9;
        misc.fromString("C:B:A:9");
        if(comp!=misc)
        throw os::smart_ptr<std::exception>(new generalTestException("C:B:A:9 build failure",locString),shared_type);
        
        //10:F:E:D
        comp[3]=16;
        comp[2]=15;
        comp[1]=14;
        comp[0]=13;
        misc.fromString("10:F:E:D");
        if(comp!=misc)
        throw os::smart_ptr<std::exception>(new generalTestException("10:F:E:D build failure",locString),shared_type);
        
        //FFFFFFFF:FFFFFFFF
        comp[3]=0;
        comp[2]=0;
        comp[1]=~0;
        comp[0]=~0;
        misc.fromString("FFFFFFFF:FFFFFFFF");
        if(comp!=misc)
            throw os::smart_ptr<std::exception>(new generalTestException("FFFFFFFF:FFFFFFFF build failure",locString),shared_type);
        
    }
    //Tests size manipulation
    void numberSizeManipulation() throw(os::smart_ptr<std::exception>)
    {
        std::string locString = "cryptoNumberTest.cpp, numberSizeManipulation()";
        number num;
        
        //Default size
        if(num.size()!=1)
            throw os::smart_ptr<std::exception>(new generalTestException("Default size incorrect",locString),shared_type);
        
        //Expand (1)
        num.expand(3);
        if(num.size()!=3)
            throw os::smart_ptr<std::exception>(new generalTestException("Expansion 1 failed",locString),shared_type);
        if(num[2]!=0 || num[1]!=0 || num[0]!=0)
            throw os::smart_ptr<std::exception>(new generalTestException("Expansion 1 values wrong",locString),shared_type);
        
        //Reduce (1)
        num.reduce();
        if(num.size()!=1)
            throw os::smart_ptr<std::exception>(new generalTestException("Reduce 1 failed",locString),shared_type);
        if(num[0]!=0)
        throw os::smart_ptr<std::exception>(new generalTestException("Reduce 1 values wrong",locString),shared_type);
        
        //Expand (2)
        num.expand(3);
        if(num.size()!=3)
            throw os::smart_ptr<std::exception>(new generalTestException("Expansion 2 failed",locString),shared_type);
        num[1]=10;
        if(num[2]!=0 || num[1]!=10 || num[0]!=0)
            throw os::smart_ptr<std::exception>(new generalTestException("Expansion 2 values wrong",locString),shared_type);
        
        //Reduce (2)
        num.reduce();
        if(num.size()!=2)
            throw os::smart_ptr<std::exception>(new generalTestException("Reduce 2 failed",locString),shared_type);
        if(num[1]!=10 || num[0]!=0)
            throw os::smart_ptr<std::exception>(new generalTestException("Reduce 2 values wrong",locString),shared_type);
        
        //Expand (3)
        num.expand(3);
        if(num.size()!=3)
        throw os::smart_ptr<std::exception>(new generalTestException("Expansion 3 failed",locString),shared_type);
        if(num[2]!=0 || num[1]!=10 || num[0]!=0)
        throw os::smart_ptr<std::exception>(new generalTestException("Expansion 3 values wrong",locString),shared_type);
    }

/*================================================================
	Integer Tests
 ================================================================*/

    //Integer type test
    void integerTypeTest() throw(os::smart_ptr<std::exception>)
    {
        std::string locString = "cryptoNumberTest.cpp, numberTypeTest()";
    
        integer num;
    
        //Check all types
        if(!num.hasCompare())
            throw os::smart_ptr<std::exception>(new generalTestException("hasCompare failed",locString),shared_type);
        if(!num.hasAddition())
            throw os::smart_ptr<std::exception>(new generalTestException("hasAddition failed",locString),shared_type);
        if(!num.hasSubtraction())
            throw os::smart_ptr<std::exception>(new generalTestException("hasSubtraction failed",locString),shared_type);
        if(!num.hasRightShift())
            throw os::smart_ptr<std::exception>(new generalTestException("hasRightShift failed",locString),shared_type);
        if(!num.hasLeftShift())
            throw os::smart_ptr<std::exception>(new generalTestException("hasLeftShift failed",locString),shared_type);
        if(!num.hasMultiplication())
            throw os::smart_ptr<std::exception>(new generalTestException("hasMultiplication failed",locString),shared_type);
        if(!num.hasDivision())
            throw os::smart_ptr<std::exception>(new generalTestException("hasDivision failed",locString),shared_type);
        if(!num.hasModulo())
            throw os::smart_ptr<std::exception>(new generalTestException("hasModulo failed",locString),shared_type);
        if(!num.hasExponentiation())
            throw os::smart_ptr<std::exception>(new generalTestException("hasExponentiation failed",locString),shared_type);
        if(!num.hasModuloExponentiation())
            throw os::smart_ptr<std::exception>(new generalTestException("hasModuloExponentiation failed",locString),shared_type);
        if(!num.hasGCD())
            throw os::smart_ptr<std::exception>(new generalTestException("hasGCD failed",locString),shared_type);
        if(!num.hasModInverse())
            throw os::smart_ptr<std::exception>(new generalTestException("hasModInverse failed",locString),shared_type);
    }

/*================================================================
	Number Test suites
 ================================================================*/

    //Basic number test
    BasicNumberTest::BasicNumberTest():
        testSuite("Basic Number")
    {
        pushTest("Type",&numberTypeTest);
        pushTest("Constructor",&numberConstructorsTest);
		pushTest("Comparison",&numberComparisonTest);
        pushTest("[] Operator",&numberArrayAccessTest);
        pushTest("To String",&numberToStringTest);
        pushTest("From String",&numberFromStringTest);
        pushTest("Size Manipulation",&numberSizeManipulation);
    }
    //Base-10 number
    IntegerTest::IntegerTest():
        testSuite("Integer")
    {
        pushTest("Type",&integerTypeTest);
    }

#endif
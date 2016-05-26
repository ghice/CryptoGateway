/**
 * @file   test/cryptoNumberTest.cpp
 * @author Jonathan Bedard
 * @date   5/26/2016
 * @brief  Testing crypto::number and crypto::integer
 * @bug No known bugs.
 *
 * This file has a series of tests which confirm
 * the functionality of crypto::integer and it's
 * base class, crypto::number.
 *
 */

///@cond INTERNAL

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

    //Randomly generate a number
    number generateNumber()
    {
        number ret=integer(8);
        //Size 8
        for(int i=0;i<4;++i)
        {
            ret[i]=rand();
        }
        return ret;
    }

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
        uint32_t arr[3];
        arr[2]=0;   arr[1]=3;   arr[0]=5;
        number num(arr,3);
        
        //Test positions
        if(num[0]!=5 && num[1]!=3)
            throw os::smart_ptr<std::exception>(new generalTestException("Read access failed!",locString),shared_type);
        
        //Overflow
        if(num[2]!=0)
            throw os::smart_ptr<std::exception>(new generalTestException("Overflow failed: "+std::to_string((long long unsigned int)num[2]),locString),shared_type);
        
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
            throw os::smart_ptr<std::exception>(new generalTestException("Reduce 1 failed, size "+std::to_string((long long unsigned int)num.size())+" value "+num.toString(),locString),shared_type);
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

    //OR Test
    void numberORTest() throw(os::smart_ptr<std::exception>)
    {
        std::string locString = "cryptoNumberTest.cpp, numberORTest()";
        
        //Variable size test
        number s1;
        number s2(4);
        number hld;
        number comp(4);
        s1[0]=4;
        s2[0]=1;
        comp[0]=5;
        s2[3]=2;
        comp[3]=2;
        
        //4 different size tests
        if((s1|s2)!=comp)
            throw os::smart_ptr<std::exception>(new generalTestException("size comp 1 wrong",locString),shared_type);
        if((s2|s1)!=comp)
            throw os::smart_ptr<std::exception>(new generalTestException("size comp 2 wrong",locString),shared_type);
        hld=s1;
        s1|=s2;
        s2|=hld;
        if(s1!=comp)
            throw os::smart_ptr<std::exception>(new generalTestException("size comp 3 wrong",locString),shared_type);
        if(s2!=comp)
            throw os::smart_ptr<std::exception>(new generalTestException("size comp 4 wrong",locString),shared_type);
        
        //Main test
        for(int i=0;i<20;++i)
        {
            number num1=generateNumber();
            number num2=generateNumber();
            number ans1=num1|num2;
            number ans2=num2|num1;
            number ans3(num1);
            
            for(int i=0;i<ans3.size();++i)
            {
                ans3[i]=num1[i]|num2[i];
            }
            number t=num1;
            num1|=num2;
            num2|=t;
                
            if(ans1!=ans3)
                throw os::smart_ptr<std::exception>(new generalTestException("ans1 wrong",locString),shared_type);
            if(ans2!=ans3)
                throw os::smart_ptr<std::exception>(new generalTestException("ans2 wrong",locString),shared_type);
            if(num1!=ans3)
                throw os::smart_ptr<std::exception>(new generalTestException("num1 wrong",locString),shared_type);
            if(num2!=ans3)
                throw os::smart_ptr<std::exception>(new generalTestException("num2 wrong",locString),shared_type);
        }
    }
    //OR Test
    void numberANDTest() throw(os::smart_ptr<std::exception>)
    {
        std::string locString = "cryptoNumberTest.cpp, numberANDTest()";
        
        //Variable size test
        number s1;
        number s2(4);
        number hld;
        number comp(4);
        s1[0]=6;
        s2[0]=3;
        comp[0]=2;
        s2[3]=2;
        comp[3]=0;
        
        //4 different size tests
        if((s1&s2)!=comp)
            throw os::smart_ptr<std::exception>(new generalTestException("size comp 1 wrong",locString),shared_type);
        if((s2&s1)!=comp)
            throw os::smart_ptr<std::exception>(new generalTestException("size comp 2 wrong",locString),shared_type);
        hld=s1;
        s1&=s2;
        s2&=hld;
        if(s1!=comp)
            throw os::smart_ptr<std::exception>(new generalTestException("size comp 3 wrong",locString),shared_type);
        if(s2!=comp)
            throw os::smart_ptr<std::exception>(new generalTestException("size comp 4 wrong",locString),shared_type);
        
        //Main test
        for(int i=0;i<20;++i)
        {
            number num1=generateNumber();
            number num2=generateNumber();
            number ans1=num1&num2;
            number ans2=num2&num1;
            number ans3(num1);
            
            for(int i=0;i<ans3.size();++i)
            {
                ans3[i]=num1[i]&num2[i];
            }
            number t=num1;
            num1&=num2;
            num2&=t;
            
            if(ans1!=ans3)
                throw os::smart_ptr<std::exception>(new generalTestException("ans1 wrong",locString),shared_type);
            if(ans2!=ans3)
                throw os::smart_ptr<std::exception>(new generalTestException("ans2 wrong",locString),shared_type);
            if(num1!=ans3)
                throw os::smart_ptr<std::exception>(new generalTestException("num1 wrong",locString),shared_type);
            if(num2!=ans3)
                throw os::smart_ptr<std::exception>(new generalTestException("num2 wrong",locString),shared_type);
        }
    }
    //XOR Test
    void numberXORTest() throw(os::smart_ptr<std::exception>)
    {
        std::string locString = "cryptoNumberTest.cpp, numberANDTest()";
        
        //Variable size test
        number s1;
        number s2(4);
        number hld;
        number comp(4);
        s1[0]=6;
        s2[0]=3;
        comp[0]=5;
        s2[3]=2;
        comp[3]=2;
        
        
        //4 different size tests
        if((s1^s2)!=comp)
            throw os::smart_ptr<std::exception>(new generalTestException("size comp 1 wrong",locString),shared_type);
        if((s2^s1)!=comp)
            throw os::smart_ptr<std::exception>(new generalTestException("size comp 2 wrong",locString),shared_type);
        hld=s1;
        s1^=s2;
        s2^=hld;
        if(s1!=comp)
            throw os::smart_ptr<std::exception>(new generalTestException("size comp 3 wrong",locString),shared_type);
        if(s2!=comp)
            throw os::smart_ptr<std::exception>(new generalTestException("size comp 4 wrong",locString),shared_type);
        
        //Main test
        for(int i=0;i<20;++i)
        {
            number num1=generateNumber();
            number num2=generateNumber();
            number ans1=num1^num2;
            number ans2=num2^num1;
            number ans3(num1);
            
            for(int i=0;i<ans3.size();++i)
            {
                ans3[i]=num1[i]^num2[i];
            }
            number t=num1;
            num1^=num2;
            num2^=t;
            
            if(ans1!=ans3)
                throw os::smart_ptr<std::exception>(new generalTestException("ans1 wrong",locString),shared_type);
            if(ans2!=ans3)
                throw os::smart_ptr<std::exception>(new generalTestException("ans2 wrong",locString),shared_type);
            if(num1!=ans3)
                throw os::smart_ptr<std::exception>(new generalTestException("num1 wrong",locString),shared_type);
            if(num2!=ans3)
            {
                testout<<num1<<std::endl;
                testout<<num2<<" == "<<ans3<<std::endl;
                throw os::smart_ptr<std::exception>(new generalTestException("num2 wrong",locString),shared_type);
            }
        }
    }
    //Tests negation
    void numberNegateTest() throw(os::smart_ptr<std::exception>)
    {
        std::string locString = "cryptoNumberTest.cpp, numberNegateTest()";
        for(int i=0;i<20;++i)
        {
            number t=generateNumber();
            number comp(t);
            
            if(t!=comp)
                throw os::smart_ptr<std::exception>(new generalTestException("Initial copy failed",locString),shared_type);
            
            t= ~t;
            if(t==comp)
                throw os::smart_ptr<std::exception>(new generalTestException("Negate equals to prev",locString),shared_type);
            
            for(int i=0;i<t.size();++i)
                comp[i]= ~comp[i];
            
            if(t!=comp)
                throw os::smart_ptr<std::exception>(new generalTestException("Negate comparison failed",locString),shared_type);
        }
    }

/*================================================================
	Integer Tests
 ================================================================*/

    //Randomly generate two integers
    void generateIntegers(integer& int1,integer& int2)
    {
        int1=integer(8);
        int2=integer(8);
        
        //Size 8
        for(int i=0;i<4;++i)
        {
            int1[i]=rand();
            int2[i]=rand();
        }
    }

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
        if(!num.checkType())
            throw os::smart_ptr<std::exception>(new generalTestException("Integer type check failed!",locString),shared_type);
    }
    //Integer compare test
    void integerCompareTest() throw(os::smart_ptr<std::exception>)
    {
        std::string locString = "cryptoNumberTest.cpp, integerCompareTest()";
        integer int1;
        integer int2;
        const struct numberType* nt=int1.numberDefinition();
        
        //Check if the integer target is valid
        if(!int1.checkType())
            throw os::smart_ptr<std::exception>(new generalTestException("Integer type check failed!",locString),shared_type);
        
        //Basic different size test
        int1.expand(4);
        int2=integer(2);
        int1[3]=2;
        int2[1]=2;
        if(int1<=int2)
            throw os::smart_ptr<std::exception>(new generalTestException("Size diff: <= failed",locString),shared_type);
        if(int1.compare(&int2)!=1)
            throw os::smart_ptr<std::exception>(new generalTestException("Size diff: compare == 1 failed",locString),shared_type);
        int1[3]=0;
        int2[0]=5;
        int2[1]=2;
        if(int1>=int2)
            throw os::smart_ptr<std::exception>(new generalTestException("Size diff: >= failed",locString),shared_type);
        if(int1.compare(&int2)!=-1)
            throw os::smart_ptr<std::exception>(new generalTestException("Size diff: compare == -1 failed",locString),shared_type);
        
        //Run compare tests, 20 iterations
        for(int i=0;i<20;++i)
        {
            integer src1;
            integer src2;
            int cpp_ans;
            int c_ans;
            generateIntegers(src1, src2);
            
            //src1 to src2
            cpp_ans=src1.compare(&src2);
            c_ans=nt->compare(src1.data(),src2.data(),src1.size());
            
            if(cpp_ans!=c_ans)
                throw os::smart_ptr<std::exception>(new generalTestException("src1 comp src2 failed",locString),shared_type);
            if(cpp_ans==0)
            {
                if(!(src1==src2)||src1!=src2)
                    throw os::smart_ptr<std::exception>(new generalTestException("Random == failure!",locString),shared_type);
            }
            else if(cpp_ans<0)
            {
                if(!(src1<src2)||src1>=src2)
                    throw os::smart_ptr<std::exception>(new generalTestException("Random < failure!",locString),shared_type);
            }
            else
            {
                if(!(src1>src2)||src1<=src2)
                    throw os::smart_ptr<std::exception>(new generalTestException("Random > failure!",locString),shared_type);
            }
        }
    }
    //Integer addition test
    void integerAdditionTest() throw(os::smart_ptr<std::exception>)
    {
        std::string locString = "cryptoNumberTest.cpp, integerAdditionTest()";
        integer int1;
        integer int2;
        const struct numberType* nt=int1.numberDefinition();
    
        //Check if the integer target is valid
        if(!int1.checkType())
            throw os::smart_ptr<std::exception>(new generalTestException("Integer type check failed!",locString),shared_type);
        
        //Quickly test a variable size example
        int1.expand(4);
        int2[0]=6;
        int1[3]=4;
        int2=int1+int2;
        int1[0]=6;
        if(int1!=int2)
            throw os::smart_ptr<std::exception>(new generalTestException("Variable size failed!",locString),shared_type);
        
        //Run compare tests, 20 iterations
        for(int i=0;i<20;++i)
        {
            integer src1;
            integer src2;
            integer ans1;
            integer ans2;
            integer ans3;
            generateIntegers(src1, src2);
            ans1=src1;
            
            //Preform 3 versions
            nt->addition(src1.data(),src2.data(),ans1.data(),src1.size());
            src1.addition(&src2,&ans2);
            ans3=src1+src2;
            src1+=src2;
            
            //ans1 is the ref value
            if(ans1!=ans2)
                throw os::smart_ptr<std::exception>(new generalTestException("OO function failed!",locString),shared_type);
            if(ans1!=ans3)
                throw os::smart_ptr<std::exception>(new generalTestException("OO operator failed!",locString),shared_type);
            if(ans1!=src1)
                throw os::smart_ptr<std::exception>(new generalTestException("Op= failed",locString),shared_type);
        }
    }
    //Integer subtraction test
    void integerSubtractionTest() throw(os::smart_ptr<std::exception>)
    {
        std::string locString = "cryptoNumberTest.cpp, integerSubtractionTest()";
        integer int1;
        integer int2;
        const struct numberType* nt=int1.numberDefinition();
    
        //Check if the integer target is valid
        if(!int1.checkType())
            throw os::smart_ptr<std::exception>(new generalTestException("Integer type check failed!",locString),shared_type);
    
        //Quickly test a variable size example
        int1.expand(4);
        int2[0]=6;
        int1[0]=8;
        int1[3]=4;
        int2=int1-int2;
        int1[0]=2;
        if(int1!=int2)
            throw os::smart_ptr<std::exception>(new generalTestException("Variable size failed!",locString),shared_type);
        
        //Run compare tests, 20 iterations
        for(int i=0;i<20;++i)
        {
            integer src1;
            integer src2;
            integer ans1;
            integer ans2;
            integer ans3;
            generateIntegers(src1, src2);
            ans1=src1;
            src1[src1.size()/2+1]=1;
        
            //Preform 3 versions
            nt->subtraction(src1.data(),src2.data(),ans1.data(),src1.size());
            src1.subtraction(&src2,&ans2);
            ans3=src1-src2;
            src1-=src2;
        
            //ans1 is the ref value
            if(ans1!=ans2)
                throw os::smart_ptr<std::exception>(new generalTestException("OO function failed!",locString),shared_type);
            if(ans1!=ans3)
                throw os::smart_ptr<std::exception>(new generalTestException("OO operator failed!",locString),shared_type);
            if(ans1!=src1)
                throw os::smart_ptr<std::exception>(new generalTestException("Op= failed",locString),shared_type);
        }
    }
    //Tests the incrementing and decrementing of an integer
    void integerIncrementTest() throw(os::smart_ptr<std::exception>)
    {
        std::string locString = "cryptoNumberTest.cpp, integerIncrementTest()";
        integer int1;
        integer int2;
        
        int1++;
        int2[0]++;
        if(int1!=int2)
            throw os::smart_ptr<std::exception>(new generalTestException("Increment fail: 1",locString),shared_type);
        
        int2[0]++;
        if(++int1!=int2)
            throw os::smart_ptr<std::exception>(new generalTestException("Increment fail: 2",locString),shared_type);
        
        if(int1++!=int2)
            throw os::smart_ptr<std::exception>(new generalTestException("Increment fail: 3",locString),shared_type);
        int2[0]++;
        
        int1--;
        int2[0]--;
        if(int1!=int2)
            throw os::smart_ptr<std::exception>(new generalTestException("Decrement fail: 1",locString),shared_type);
        
        int2[0]--;
        if(--int1!=int2)
            throw os::smart_ptr<std::exception>(new generalTestException("Decrement fail: 2",locString),shared_type);
        
        if(int1--!=int2)
            throw os::smart_ptr<std::exception>(new generalTestException("Decrement fail: 3",locString),shared_type);
        int2[0]--;
    }
    //Integer subtraction test
    void integerRightShiftTest() throw(os::smart_ptr<std::exception>)
    {
        std::string locString = "cryptoNumberTest.cpp, integerRightShiftTest()";
        integer int1;
        const struct numberType* nt=int1.numberDefinition();
        
        //Check if the integer target is valid
        if(!int1.checkType())
            throw os::smart_ptr<std::exception>(new generalTestException("Integer type check failed!",locString),shared_type);
        
        //Run compare tests, 20 iterations
        for(int i=0;i<20;++i)
        {
            integer src1;
            integer src2;
            integer ans1;
            integer ans2;
            integer ans3;
            uint16_t rshift=rand()%128;
            
            generateIntegers(src1, src2);
            ans1=src1;
            src1[src1.size()/2+1]=1;
            
            //Preform 3 versions
            nt->rightShift(src1.data(),rshift,ans1.data(),src1.size());
            src1.rightShift(rshift,&ans2);
            ans3=src1>>rshift;
            
            //ans1 is the ref value
            if(ans1!=ans2)
                throw os::smart_ptr<std::exception>(new generalTestException("OO function failed!",locString),shared_type);
            if(ans1!=ans3)
                throw os::smart_ptr<std::exception>(new generalTestException("OO operator failed!",locString),shared_type);
        }
    }
    //Integer left shift test
    void integerLeftShiftTest() throw(os::smart_ptr<std::exception>)
    {
        std::string locString = "cryptoNumberTest.cpp, integerLeftShiftTest()";
        integer int1;
        const struct numberType* nt=int1.numberDefinition();
        
        //Check if the integer target is valid
        if(!int1.checkType())
            throw os::smart_ptr<std::exception>(new generalTestException("Integer type check failed!",locString),shared_type);
        
        //Run compare tests, 20 iterations
        for(int i=0;i<20;++i)
        {
            integer src1;
            integer src2;
            integer ans1;
            integer ans2;
            integer ans3;
            uint16_t rshift=rand()%128;
            
            generateIntegers(src1, src2);
            ans1=src1;
            src1[src1.size()/2+1]=1;
            
            //Preform 3 versions
            nt->rightShift(src1.data(),rshift,ans1.data(),src1.size());
            src1.rightShift(rshift,&ans2);
            ans3=src1>>rshift;
            
            //ans1 is the ref value
            if(ans1!=ans2)
                throw os::smart_ptr<std::exception>(new generalTestException("OO function failed!",locString),shared_type);
            if(ans1!=ans3)
                throw os::smart_ptr<std::exception>(new generalTestException("OO operator failed!",locString),shared_type);
        }
    }
    //Integer multiplicaiton test
    void integerMultiplicationTest() throw(os::smart_ptr<std::exception>)
    {
        std::string locString = "cryptoNumberTest.cpp, integerMultiplicationTest()";
        integer int1;
        integer int2;
        const struct numberType* nt=int1.numberDefinition();
        
        //Check if the integer target is valid
        if(!int1.checkType())
            throw os::smart_ptr<std::exception>(new generalTestException("Integer type check failed!",locString),shared_type);
        
        //Quickly test a variable size example
        int1.expand(4);
        int2[0]=2;
        int1[3]=4;
        int2=int1*int2;
        int1[3]=8;
        if(int1!=int2)
            throw os::smart_ptr<std::exception>(new generalTestException("Variable size failed!",locString),shared_type);
        
        //Run compare tests, 20 iterations
        for(int i=0;i<20;++i)
        {
            integer src1;
            integer src2;
            integer ans1;
            integer ans2;
            integer ans3;
            generateIntegers(src1, src2);
            ans1=src1;
            
            //Preform 3 versions
            nt->multiplication(src1.data(),src2.data(),ans1.data(),src1.size());
            src1.multiplication(&src2,&ans2);
            ans3=src1*src2;
            src1*=src2;
            
            //ans1 is the ref value
            if(ans1!=ans2)
                throw os::smart_ptr<std::exception>(new generalTestException("OO function failed!",locString),shared_type);
            if(ans1!=ans3)
                throw os::smart_ptr<std::exception>(new generalTestException("OO operator failed!",locString),shared_type);
            if(ans1!=src1)
                throw os::smart_ptr<std::exception>(new generalTestException("Op= failed",locString),shared_type);
        }
    }
    //Integer division test
    void integerDivisionTest() throw(os::smart_ptr<std::exception>)
    {
        std::string locString = "cryptoNumberTest.cpp, integerDivisionTest()";
        integer int1;
        integer int2;
        const struct numberType* nt=int1.numberDefinition();
        
        //Check if the integer target is valid
        if(!int1.checkType())
            throw os::smart_ptr<std::exception>(new generalTestException("Integer type check failed!",locString),shared_type);
        
        //Quickly test a variable size example
        int1.expand(4);
        int2[0]=2;
        int1[3]=6;
        int2=int1/int2;
        int1[3]=3;
        if(int1!=int2)
            throw os::smart_ptr<std::exception>(new generalTestException("Variable size failed!",locString),shared_type);
        
        //Run compare tests, 20 iterations
        for(int i=0;i<20;++i)
        {
            integer src1;
            integer src2;
            integer ans1;
            integer ans2;
            integer ans3;
            generateIntegers(src1, src2);
            ans1=src1;
            
            //Preform 3 versions
            nt->division(src1.data(),src2.data(),ans1.data(),src1.size());
            src1.division(&src2,&ans2);
            ans3=src1/src2;
            src1/=src2;
            
            //ans1 is the ref value
            if(ans1!=ans2)
                throw os::smart_ptr<std::exception>(new generalTestException("OO function failed!",locString),shared_type);
            if(ans1!=ans3)
                throw os::smart_ptr<std::exception>(new generalTestException("OO operator failed!",locString),shared_type);
            if(ans1!=src1)
                throw os::smart_ptr<std::exception>(new generalTestException("Op= failed",locString),shared_type);
        }
    }
    //Integer modulo test
    void integerModuloTest() throw(os::smart_ptr<std::exception>)
    {
        std::string locString = "cryptoNumberTest.cpp, integerModuloTest()";
        integer int1;
        integer int2;
        const struct numberType* nt=int1.numberDefinition();
        
        //Check if the integer target is valid
        if(!int1.checkType())
            throw os::smart_ptr<std::exception>(new generalTestException("Integer type check failed!",locString),shared_type);
        
        //Quickly test a variable size example
        int1.expand(4);
        int2[0]=5;
        int1[0]=9;
        int1[3]=4;
        int2=int1%int2;
        int1[3]=0;
        int1[0]=3;
        if(int1!=int2)
            throw os::smart_ptr<std::exception>(new generalTestException("Variable size failed!",locString),shared_type);
        
        //Run compare tests, 20 iterations
        for(int i=0;i<20;++i)
        {
            integer src1;
            integer src2;
            integer ans1;
            integer ans2;
            integer ans3;
            generateIntegers(src1, src2);
            ans1=src1;
            
            //Preform 3 versions
            nt->modulo(src1.data(),src2.data(),ans1.data(),src1.size());
            src1.modulo(&src2,&ans2);
            ans3=src1%src2;
            src1%=src2;
            
            //ans1 is the ref value
            if(ans1!=ans2)
                throw os::smart_ptr<std::exception>(new generalTestException("OO function failed!",locString),shared_type);
            if(ans1!=ans3)
                throw os::smart_ptr<std::exception>(new generalTestException("OO operator failed!",locString),shared_type);
            if(ans1!=src1)
                throw os::smart_ptr<std::exception>(new generalTestException("Op= failed",locString),shared_type);
        }
    }
    //Integer exponentiation test
    void integerExponentiationTest() throw(os::smart_ptr<std::exception>)
    {
        std::string locString = "cryptoNumberTest.cpp, integerModuloTest()";
        integer int1;
        integer int2;
        const struct numberType* nt=int1.numberDefinition();
        
        //Check if the integer target is valid
        if(!int1.checkType())
            throw os::smart_ptr<std::exception>(new generalTestException("Integer type check failed!",locString),shared_type);
        
        //Quickly test a variable size example
        int1.expand(4);
        int2[0]=3;
        int1[1]=3;
        int2=int1.exponentiation(int2);
        int1.expand(4);
        int1[1]=0;
        int1[3]=27;
        if(int1!=int2)
            throw os::smart_ptr<std::exception>(new generalTestException("Variable size failed!",locString),shared_type);
        
        //Run compare tests, 20 iterations
        for(int i=0;i<20;++i)
        {
            integer src1;
            integer src2;
            integer ans1;
            integer ans2;
            integer ans3;
            generateIntegers(src1, src2);
            src1[3]=0;  src1[2]=0;  src1[1]=0;
            src2[3]=0;  src2[2]=0;  src2[1]=0;  src2[0]%=5;
            ans1=src1;
            
            //Preform 3 versions
            nt->exponentiation(src1.data(),src2.data(),ans1.data(),src1.size());
            src1.number::exponentiation(&src2,&ans2);
            ans3=src1.exponentiation(src2);
            src1.exponentiationEquals(src2);
            
            //ans1 is the ref value
            if(ans1!=ans2)
                throw os::smart_ptr<std::exception>(new generalTestException("OO function failed!",locString),shared_type);
            if(ans1!=ans3)
                throw os::smart_ptr<std::exception>(new generalTestException("OO operator failed!",locString),shared_type);
            if(ans1!=src1)
                throw os::smart_ptr<std::exception>(new generalTestException("Op= failed",locString),shared_type);
        }
    }
    //Integer mod-exponentiation test
    void integerModuloExponentiationTest() throw(os::smart_ptr<std::exception>)
    {
        std::string locString = "cryptoNumberTest.cpp, integerModuloExponentiationTest()";
        integer int1;
        integer int2;
        integer int3;
        const struct numberType* nt=int1.numberDefinition();
        
        //Check if the integer target is valid
        if(!int1.checkType())
            throw os::smart_ptr<std::exception>(new generalTestException("Integer type check failed!",locString),shared_type);
        
        //Quickly test a variable size example
        int1.expand(4);
        int3[0]=2;
        int2[0]=11;
        int1[1]=4;
        int1[0]=3;
        int2=int1.moduloExponentiation(int2, int3);
        int1[1]=0;
        int1[0]=1;
        if(int1!=int2)
            throw os::smart_ptr<std::exception>(new generalTestException("Variable size failed!",locString),shared_type);
        
        //Run compare tests, 20 iterations
        for(int i=0;i<20;++i)
        {
            integer src1;
            integer src2;
            integer src3;
            integer ans1;
            integer ans2;
            integer ans3;
            generateIntegers(src1, src2);
            generateIntegers(src2,src3);
            ans1=src1;
            
            //Preform 3 versions
            nt->moduloExponentiation(src1.data(),src2.data(),src3.data(),ans1.data(),src1.size());
            src1.number::moduloExponentiation(&src2,&src3,&ans2);
            ans3=src1.moduloExponentiation(src2,src3);
            src1.moduloExponentiationEquals(src2,src3);
            
            //ans1 is the ref value
            if(ans1!=ans2)
                throw os::smart_ptr<std::exception>(new generalTestException("OO function failed!",locString),shared_type);
            if(ans1!=ans3)
                throw os::smart_ptr<std::exception>(new generalTestException("OO operator failed!",locString),shared_type);
            if(ans1!=src1)
                throw os::smart_ptr<std::exception>(new generalTestException("Op= failed",locString),shared_type);
        }
    }
    //Integer gcd test
    void integerGCDTest() throw(os::smart_ptr<std::exception>)
    {
        std::string locString = "cryptoNumberTest.cpp, integerGCDTest()";
        integer int1;
        integer int2;
        const struct numberType* nt=int1.numberDefinition();
        
        //Check if the integer target is valid
        if(!int1.checkType())
            throw os::smart_ptr<std::exception>(new generalTestException("Integer type check failed!",locString),shared_type);
        
        //Quickly test a variable size example
        int1.expand(4);
        int2[0]=6;
        int1[3]=4;
        int2=int1.gcd(int2);
        int1[3]=0;
        int1[0]=2;
        if(int1!=int2)
            throw os::smart_ptr<std::exception>(new generalTestException("Variable size failed!",locString),shared_type);
        
        //Run compare tests, 20 iterations
        for(int i=0;i<20;++i)
        {
            integer src1;
            integer src2;
            integer ans1;
            integer ans2;
            integer ans3;
            generateIntegers(src1, src2);
            ans1=src1;
            
            //Preform 3 versions
            nt->gcd(src1.data(),src2.data(),ans1.data(),src1.size());
            src1.number::gcd(&src2,&ans2);
            ans3=src1.gcd(src2);
            src1.gcdEquals(src2);
            
            //ans1 is the ref value
            if(ans1!=ans2)
                throw os::smart_ptr<std::exception>(new generalTestException("OO function failed!",locString),shared_type);
            if(ans1!=ans3)
                throw os::smart_ptr<std::exception>(new generalTestException("OO operator failed!",locString),shared_type);
            if(ans1!=src1)
                throw os::smart_ptr<std::exception>(new generalTestException("Op= failed",locString),shared_type);
        }
    }
    //Integer modInver test
    void integerModInverseTest() throw(os::smart_ptr<std::exception>)
    {
        std::string locString = "cryptoNumberTest.cpp, integerModInverseTest()";
        integer int1;
        integer int2;
        const struct numberType* nt=int1.numberDefinition();
        
        //Check if the integer target is valid
        if(!int1.checkType())
            throw os::smart_ptr<std::exception>(new generalTestException("Integer type check failed!",locString),shared_type);
        
        //Quickly test a variable size example
        int1.expand(4);
        int2[0]=17;
        int1[3]=4;
        int1%=int2;
        int2=int1.modInverse(int2);
        int1[3]=0;
        int1[0]=13;
        if(int1!=int2)
            throw os::smart_ptr<std::exception>(new generalTestException("Variable size failed!",locString),shared_type);
        
        //Run compare tests, 20 iterations
        for(int i=0;i<20;++i)
        {
            integer src1;
            integer src2;
            integer ans1;
            integer ans2;
            integer ans3;
            src1[0]=rand();
            src2[0]=7919;
            
            //Preform 3 versions
            nt->modInverse(src1.data(),src2.data(),ans1.data(),src1.size());
            src1.number::modInverse(&src2,&ans2);
            ans3=src1.modInverse(src2);
            src1.modInverseEquals(src2);
            
            //ans1 is the ref value
            if(ans1!=ans2)
                throw os::smart_ptr<std::exception>(new generalTestException("OO function failed!",locString),shared_type);
            if(ans1!=ans3)
                throw os::smart_ptr<std::exception>(new generalTestException("OO operator failed!",locString),shared_type);
            if(ans1!=src1)
                throw os::smart_ptr<std::exception>(new generalTestException("Op= failed",locString),shared_type);
        }
    }
    //Prime test
    void integerPrimeTest() throw(os::smart_ptr<std::exception>)
    {
        std::string locString = "cryptoNumberTest.cpp, integerPrimeTest()";
        integer int1;
        const struct numberType* nt=int1.numberDefinition();
        
        //Check if the integer target is valid
        if(!int1.checkType())
            throw os::smart_ptr<std::exception>(new generalTestException("Integer type check failed!",locString),shared_type);
        
        //Run prime tests, 20 iterations
        for(int i=0;i<20;++i)
        {
            integer src1;
            integer src2;
            bool ans1;
            bool ans2;
            generateIntegers(src1, src2);
            
            //Preform 3 versions
            ans1=primeTest(src1.data(),crypto::algo::primeTestCycle,src1.size());
            ans2=src1.prime();
            
            //ans1 is the ref value
            if(ans1!=ans2)
                throw os::smart_ptr<std::exception>(new generalTestException("OO function failed!",locString),shared_type);
        }
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
        
        pushTest("OR Operator",&numberORTest);
        pushTest("AND Operator",&numberANDTest);
        pushTest("XOR Operator",&numberXORTest);
        pushTest("Negate Operator",&numberNegateTest);
    }
    //Base-10 number
    IntegerTest::IntegerTest():
        testSuite("Integer")
    {
        pushTest("Type",&integerTypeTest);
        pushTest("Integer Compare",&integerCompareTest);
        pushTest("Addition",&integerAdditionTest);
        pushTest("Subtraction",&integerSubtractionTest);
        pushTest("Increment",&integerIncrementTest);
        pushTest("Right Shift",&integerRightShiftTest);
        pushTest("Left Shift",&integerLeftShiftTest);
        pushTest("Multiplication",&integerMultiplicationTest);
        pushTest("Division",&integerDivisionTest);
        pushTest("Modulo",&integerModuloTest);
        pushTest("Exponentiation",&integerExponentiationTest);
        pushTest("Modulo Exponentiation",&integerModuloExponentiationTest);
        pushTest("GCD",&integerGCDTest);
        pushTest("Modulo Inverse",&integerModInverseTest);
        pushTest("Prime",&integerPrimeTest);
    }

#endif

///@endcond
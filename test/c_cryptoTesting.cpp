/**
 * @file   test/c_cryptoTesting.cpp
 * @author Jonathan Bedard
 * @date   2/12/2016
 * @brief  Implementation for C file testing
 * @bug No known bugs.
 *
 * This file implements test suites which
 * are testing raw C code.  This file
 * currently tests the Base-Ten suite.
 *
 */

///@cond INTERNAL

#ifndef C_CRYPTO_TESTING_CPP
#define C_CRYPTO_TESTING_CPP

#include "cryptoConstants.h"
#include "c_cryptoTesting.h"
#include <string>

using namespace test;
using namespace os;
using namespace crypto;

    //Confirms NULL value
    void nullNumberType() throw(os::smart_ptr<std::exception>)
    {
        std::string locString = "c_cryptoTesting.cpp, nullNumberType()";
        struct numberType* _nullType = buildNullNumberType();
        if(_nullType == NULL) throw os::smart_ptr<std::exception>(new generalTestException("NULL type could not be built!",locString),shared_type);
        
        if(_nullType->typeID != crypto::numberType::Default) throw os::smart_ptr<std::exception>(new generalTestException("NULL type ID wrong!",locString),shared_type);
		if(std::string(_nullType->name) != numberName::Default) throw os::smart_ptr<std::exception>(new generalTestException("NULL type name wrong!",locString),shared_type);
        
        if(_nullType->compare != NULL) throw os::smart_ptr<std::exception>(new generalTestException("NULL type compare defined!!",locString),shared_type);
        
        if(_nullType->addition != NULL) throw os::smart_ptr<std::exception>(new generalTestException("NULL type addition defined!!",locString),shared_type);
        if(_nullType->subtraction != NULL) throw os::smart_ptr<std::exception>(new generalTestException("NULL type subtraction defined!!",locString),shared_type);
        
        if(_nullType->rightShift != NULL) throw os::smart_ptr<std::exception>(new generalTestException("NULL type right shift defined!!",locString),shared_type);
        if(_nullType->leftShift != NULL) throw os::smart_ptr<std::exception>(new generalTestException("NULL type left shift defined!!",locString),shared_type);
        
        if(_nullType->multiplication != NULL) throw os::smart_ptr<std::exception>(new generalTestException("NULL type multiplication defined!!",locString),shared_type);
        if(_nullType->division != NULL) throw os::smart_ptr<std::exception>(new generalTestException("NULL type division defined!!",locString),shared_type);
		if(_nullType->modulo != NULL) throw os::smart_ptr<std::exception>(new generalTestException("NULL type modulo defined!!",locString),shared_type);

		if(_nullType->exponentiation != NULL) throw os::smart_ptr<std::exception>(new generalTestException("NULL type exponentiation defined!!",locString),shared_type);
		if(_nullType->moduloExponentiation != NULL) throw os::smart_ptr<std::exception>(new generalTestException("NULL type moduloExponentiation defined!!",locString),shared_type);

		if(_nullType->gcd != NULL) throw os::smart_ptr<std::exception>(new generalTestException("NULL type gcd defined!!",locString),shared_type);
		if(_nullType->modInverse != NULL) throw os::smart_ptr<std::exception>(new generalTestException("NULL type modInverse defined!!",locString),shared_type);
    }
    //Checks if the base-10 type is constructed properly
    struct numberType* typeCheckBase10(bool errorType=false)throw(os::smart_ptr<std::exception>)
    {
        std::string locString = "c_cryptoTesting.cpp, typeCheckBase10(...)";
        struct numberType* _baseType = buildBaseTenType();
        os::smart_ptr<std::exception> defThrow = os::smart_ptr<std::exception>(new generalTestException("Base-10 type error!",locString),shared_type);
        
        if(_baseType == NULL)
        {
            if(errorType) throw os::smart_ptr<std::exception>(new generalTestException("Base-10 type could not be built!",locString),shared_type);
            else throw defThrow;
        }
        
        if(_baseType->typeID != crypto::numberType::Base10)
        {
            if(errorType) throw os::smart_ptr<std::exception>(new generalTestException("Base-10 type ID wrong!",locString),shared_type);
            else throw defThrow;
        }
		if(std::string(_baseType->name) != numberName::Base10)
        {
            if(errorType) throw os::smart_ptr<std::exception>(new generalTestException("Base-10 type name wrong!",locString),shared_type);
            else throw defThrow;
        }
        
        if(_baseType->compare == NULL)
        {
            if(errorType) throw os::smart_ptr<std::exception>(new generalTestException("Base-10 type compare undefined!",locString),shared_type);
            else throw defThrow;
        }
        
        if(_baseType->addition == NULL)
        {
            if(errorType) throw os::smart_ptr<std::exception>(new generalTestException("Base-10 type addition undefined!",locString),shared_type);
            else throw defThrow;
        }
        if(_baseType->subtraction == NULL)
        {
            if(errorType) throw os::smart_ptr<std::exception>(new generalTestException("Base-10 type addition undefined!",locString),shared_type);
            else throw defThrow;
        }
        
        if(_baseType->rightShift == NULL)
        {
            if(errorType) throw os::smart_ptr<std::exception>(new generalTestException("Base-10 type right shift undefined!",locString),shared_type);
            else throw defThrow;
        }
        if(_baseType->leftShift == NULL)
        {
            if(errorType) throw os::smart_ptr<std::exception>(new generalTestException("Base-10 type left shift undefined!",locString),shared_type);
            else throw defThrow;
        }
        
        if(_baseType->multiplication == NULL)
        {
            if(errorType) throw os::smart_ptr<std::exception>(new generalTestException("Base-10 type multiplication undefined!!",locString),shared_type);
            else throw defThrow;
        }
        if(_baseType->division == NULL)
        {
            if(errorType) throw os::smart_ptr<std::exception>(new generalTestException("Base-10 type division undefined!!",locString),shared_type);
            else throw defThrow;
        }
		if(_baseType->modulo == NULL)
        {
            if(errorType) throw os::smart_ptr<std::exception>(new generalTestException("Base-10 type modulo undefined!!",locString),shared_type);
            else throw defThrow;
        }

		if(_baseType->exponentiation == NULL)
        {
            if(errorType) throw os::smart_ptr<std::exception>(new generalTestException("Base-10 type exponentiation undefined!!",locString),shared_type);
            else throw defThrow;
        }
		if(_baseType->moduloExponentiation == NULL)
        {
            if(errorType) throw os::smart_ptr<std::exception>(new generalTestException("Base-10 type moduloExponentiation undefined!!",locString),shared_type);
            else throw defThrow;
        }

		if(_baseType->gcd == NULL)
        {
            if(errorType) throw os::smart_ptr<std::exception>(new generalTestException("Base-10 type gcd undefined!!",locString),shared_type);
            else throw defThrow;
        }
		if(_baseType->modInverse == NULL)
        {
            if(errorType) throw os::smart_ptr<std::exception>(new generalTestException("Base-10 type modInverse undefined!!",locString),shared_type);
            else throw defThrow;
        }
        
        return _baseType;
    }
    void typeCheckBase10Test() throw(os::smart_ptr<std::exception>)
    {
        typeCheckBase10(true);
    }
    //Compare test
    void base10compareTest() throw(os::smart_ptr<std::exception>)
    {
        struct numberType* _baseType = typeCheckBase10();
        std::string locString = "c_cryptoTesting.cpp, base10compareTest()";
    
        uint32_t src1[4];
        uint32_t src2[4];
    
        src1[3]=0;  src1[2]=0;  src1[1]=0;  src1[0]=0;
        src2[3]=0;  src2[2]=0;  src2[1]=0;  src2[0]=0;
    
        //0==0
        if(_baseType->compare(src1,src2,4)!=0)
            throw os::smart_ptr<std::exception>(new generalTestException("0==0 failed!",locString),shared_type);
        //0<1
        src2[0]=1;
        if(_baseType->compare(src1,src2,4)!=-1)
            throw os::smart_ptr<std::exception>(new generalTestException("0<1 failed!",locString),shared_type);
        //2>1
        src1[0]=2;
        if(_baseType->compare(src1,src2,4)!=1)
            throw os::smart_ptr<std::exception>(new generalTestException("2>1 failed!",locString),shared_type);
        //2==2
        src2[0]=2;
        if(_baseType->compare(src1,src2,4)!=0)
            throw os::smart_ptr<std::exception>(new generalTestException("2==2 failed!",locString),shared_type);
        
        //0:0:0:2<1:0:0:2
        src2[3]=1;
        if(_baseType->compare(src1,src2,4)!=-1)
            throw os::smart_ptr<std::exception>(new generalTestException("0:0:0:2<1:0:0:2 failed!",locString),shared_type);
        //2:0:0:2<1:0:0:2
        src1[3]=2;
        if(_baseType->compare(src1,src2,4)!=1)
            throw os::smart_ptr<std::exception>(new generalTestException("2:0:0:2<1:0:0:2 failed!",locString),shared_type);
        //2:0:0:2==2:0:0:2
        src2[3]=2;
        if(_baseType->compare(src1,src2,4)!=0)
            throw os::smart_ptr<std::exception>(new generalTestException("2:0:0:2==2:0:0:2 failed!",locString),shared_type);
        
        //2:0:0:2<2:0:0:3
        src2[0]=3;
        if(_baseType->compare(src1,src2,4)!=-1)
            throw os::smart_ptr<std::exception>(new generalTestException("2:0:0:2<2:0:0:3 failed!",locString),shared_type);
        //2:0:0:4<2:0:0:3
        src1[0]=4;
        if(_baseType->compare(src1,src2,4)!=1)
            throw os::smart_ptr<std::exception>(new generalTestException("2:0:0:4<2:0:0:3 failed!",locString),shared_type);
        //2:0:0:4==2:0:0:4
        src2[0]=4;
        if(_baseType->compare(src1,src2,4)!=0)
            throw os::smart_ptr<std::exception>(new generalTestException("2:0:0:4==2:0:0:4 failed!",locString),shared_type);
    }
    //Addition test
    void base10additionTest() throw(os::smart_ptr<std::exception>)
    {
        struct numberType* _baseType = typeCheckBase10();
        std::string locString = "c_cryptoTesting.cpp, base10additionTest()";
        
        uint32_t src1[4];
        uint32_t src2[4];
        uint32_t dest1[4];
        uint32_t dest2[4];
        int ret;
        
        src1[3]=0;  src1[2]=0;  src1[1]=0;  src1[0]=0;
        src2[3]=0;  src2[2]=0;  src2[1]=0;  src2[0]=0;
        
        //0+0
        ret=_baseType->addition(src1,src2,dest1,4);
        if(_baseType->compare(src1,dest1,4)!=0 || !ret)
            throw os::smart_ptr<std::exception>(new generalTestException("0+0 failed!",locString),shared_type);
        
        //0+4
        src2[0]=4;
        ret=_baseType->addition(src1,src2,dest1,4);
        if(_baseType->compare(src2,dest1,4)!=0 || !ret)
            throw os::smart_ptr<std::exception>(new generalTestException("0+4 failed!",locString),shared_type);
        //4+0
        ret=_baseType->addition(src2,src1,dest1,4);
        if(_baseType->compare(src2,dest1,4)!=0 || !ret)
            throw os::smart_ptr<std::exception>(new generalTestException("4+0 failed!",locString),shared_type);
        
        //4+4
        src1[0]=4;
        ret=_baseType->addition(src1,src2,dest1,4);
        src2[0]=8;
        if(_baseType->compare(src2,dest1,4)!=0 || !ret)
            throw os::smart_ptr<std::exception>(new generalTestException("4+4 failed!",locString),shared_type);
        
        //Carry
        src1[0]= (uint32_t) -1;
        src2[0]=1;
        ret=_baseType->addition(src1,src2,dest1,4);
        ret=ret&_baseType->addition(src2,src1,dest2,4);
        src1[0]=0;
        src1[1]=1;
        if(_baseType->compare(src1,dest1,4)!=0 || _baseType->compare(dest1,dest2,4)!=0 || !ret)
            throw os::smart_ptr<std::exception>(new generalTestException("Carry failed!",locString),shared_type);
        
        //Double Carry
        src1[0]= (uint32_t) -1;
        src1[1]= (uint32_t) -1;
        src2[0]=1;
        ret=_baseType->addition(src1,src2,dest1,4);
        ret=ret&_baseType->addition(src2,src1,dest2,4);
        src1[0]=0;
        src1[1]=0;
        src1[2]=1;
        if(_baseType->compare(src1,dest1,4)!=0 || _baseType->compare(dest1,dest2,4)!=0 || !ret)
            throw os::smart_ptr<std::exception>(new generalTestException("Double carry failed!",locString),shared_type);
        
        //Overflow
        src1[0]= (uint32_t) -1;
        src1[1]= (uint32_t) -1;
        src1[2]= (uint32_t) -1;
        src1[3]= (uint32_t) -1;
        src2[0]=1;
        ret=_baseType->addition(src1,src2,dest1,4);
        ret=ret|_baseType->addition(src2,src1,dest2,4);
        src2[0]=0;
        if(_baseType->compare(src2,dest1,4)!=0 || _baseType->compare(dest1,dest2,4)!=0 || ret)
            throw os::smart_ptr<std::exception>(new generalTestException("Overflow failed!",locString),shared_type);
    }
    //Subtraction test
    void base10subtractionTest() throw(os::smart_ptr<std::exception>)
    {
        struct numberType* _baseType = typeCheckBase10();
        std::string locString = "c_cryptoTesting.cpp, base10subtractionTest()";
        
        uint32_t src1[4];
        uint32_t src2[4];
        uint32_t dest1[4];
        uint32_t dest2[4];
        int ret;
        
        src1[3]=0;  src1[2]=0;  src1[1]=0;  src1[0]=0;
        src2[3]=0;  src2[2]=0;  src2[1]=0;  src2[0]=0;
        
        //0-0
        ret = _baseType->subtraction(src1,src2,dest1,4);
        if(_baseType->compare(src1,dest1,4)!=0 || !ret)
            throw os::smart_ptr<std::exception>(new generalTestException("0-0 failed!",locString),shared_type);
        
        //4-0
        src1[0]=4;
        ret = _baseType->subtraction(src1,src2,dest1,4);
        if(_baseType->compare(src1,dest1,4)!=0 || !ret)
            throw os::smart_ptr<std::exception>(new generalTestException("4-0 failed!",locString),shared_type);
        //0-4
        src1[0]=0;
        src2[0]=4;
        ret = _baseType->subtraction(src1,src2,dest1,4);
        if(ret)
            throw os::smart_ptr<std::exception>(new generalTestException("0-4 didn't overflow!",locString),shared_type);
        ret = _baseType->addition(dest1,src2,dest2,4);
        if(ret || _baseType->compare(src1,dest2,4)!=0)
            throw os::smart_ptr<std::exception>(new generalTestException("Overflow carries from 0-4 are incorrect!",locString),shared_type);
    }
    //Left shift test
    void base10leftShiftTest() throw(os::smart_ptr<std::exception>)
    {
        struct numberType* _baseType = typeCheckBase10();
        std::string locString = "c_cryptoTesting.cpp, base10rightShiftTest()";
    
        uint32_t src1[4];
        uint32_t src2[4];
        uint32_t dest1[4];
        uint32_t dest2[4];
        int ret;
    
        src1[3]=0;  src1[2]=0;  src1[1]=0;  src1[0]=0;
        src2[3]=0;  src2[2]=0;  src2[1]=0;  src2[0]=0;
        
        //1<<1
        src1[0]=1;
        src2[0]=2;
        ret = _baseType->leftShift(src1,1,dest1,4);
        if(_baseType->compare(src2,dest1,4)!=0 || !ret)
            throw os::smart_ptr<std::exception>(new generalTestException("1<<1 failed!",locString),shared_type);
        
        //1<<32
        src1[0]=1;
        src2[0]=0;
        src2[1]=1;
        ret = _baseType->leftShift(src1,32,dest1,4);
        if(_baseType->compare(src2,dest1,4)!=0 || !ret)
            throw os::smart_ptr<std::exception>(new generalTestException("1<<32 failed!",locString),shared_type);
        
        //1<<33
        src1[0]=1;
        src2[1]=2;
        ret = _baseType->leftShift(src1,33,dest1,4);
        if(_baseType->compare(src2,dest1,4)!=0 || !ret)
            throw os::smart_ptr<std::exception>(new generalTestException("1<<33 failed!",locString),shared_type);
        
        //Split Shift
        src1[0]=1|(1<<31);
        src2[0]=0;
        src2[1]=2;
        src2[2]=1;
        ret = _baseType->leftShift(src1,33,dest1,4);
        if(_baseType->compare(src2,dest1,4)!=0 || !ret)
            throw os::smart_ptr<std::exception>(new generalTestException("Split shift failed!",locString),shared_type);
        
        //Split Shift 2
        src1[0]=1|(1<<31);
        src2[0]=0;
        src2[1]=0;
        src2[2]=2;
        src2[3]=1;
        ret = _baseType->leftShift(src1,65,dest1,4);
        if(_baseType->compare(src2,dest1,4)!=0 || !ret)
            throw os::smart_ptr<std::exception>(new generalTestException("Split shift 2 failed!",locString),shared_type);
        
        //Overflow (a little)
        ret = _baseType->leftShift(src1,97,dest1,4);
        if(ret)
            throw os::smart_ptr<std::exception>(new generalTestException("Overflow (a little) failed!",locString),shared_type);
        
        //Overflow (a lot)
        src1[0]=0;
        src1[1]=1;
        ret = _baseType->leftShift(src1,129,dest1,4);
        if(ret)
            throw os::smart_ptr<std::exception>(new generalTestException("Overflow (a lot) failed!",locString),shared_type);
        
    }
    //Right shift test
    void base10rightShiftTest() throw(os::smart_ptr<std::exception>)
    {
        struct numberType* _baseType = typeCheckBase10();
        std::string locString = "c_cryptoTesting.cpp, base10leftShiftTest()";
    
        uint32_t src1[4];
        uint32_t src2[4];
        uint32_t dest1[4];
        uint32_t dest2[4];
        int ret;
    
        src1[3]=0;  src1[2]=0;  src1[1]=0;  src1[0]=0;
        src2[3]=0;  src2[2]=0;  src2[1]=0;  src2[0]=0;
        
        //1>>1
        src1[0]=1;
		ret = _baseType->rightShift(src1,1,dest1,4);
        if(_baseType->compare(src2,dest1,4)!=0 || !ret)
            throw os::smart_ptr<std::exception>(new generalTestException("1>>1 failed!",locString),shared_type);
        
        //2>>1
        src1[0]=2;
        src2[0]=1;
        ret = _baseType->rightShift(src1,1,dest1,4);
        if(_baseType->compare(src2,dest1,4)!=0 || !ret)
            throw os::smart_ptr<std::exception>(new generalTestException("2>>1 failed!",locString),shared_type);
        
        //0:0:1:0>>32
        src1[0]=0;
        src1[1]=1;
        ret = _baseType->rightShift(src1,32,dest1,4);
        if(_baseType->compare(src2,dest1,4)!=0 || !ret)
            throw os::smart_ptr<std::exception>(new generalTestException("0:0:1:0>>32 failed!",locString),shared_type);
        
        //0:0:1:0>>31
        src1[0]=0;
        src1[1]=1;
        src2[0]=2;
        ret = _baseType->rightShift(src1,31,dest1,4);
        if(_baseType->compare(src2,dest1,4)!=0 || !ret)
            throw os::smart_ptr<std::exception>(new generalTestException("0:0:1:0>>31 failed!",locString),shared_type);
        
        //0:3:0:0>>33
        src1[0]=0;
        src1[1]=0;
        src1[2]=3;
        src2[0]=1<<31;
        src2[1]=1;
        ret = _baseType->rightShift(src1,33,dest1,4);
        if(_baseType->compare(src2,dest1,4)!=0 || !ret)
            throw os::smart_ptr<std::exception>(new generalTestException("0:3:0:0>>33 failed!",locString),shared_type);
    }
    //Multiplication test
    void base10multiplicationTest() throw(os::smart_ptr<std::exception>)
    {
        struct numberType* _baseType = typeCheckBase10();
        std::string locString = "c_cryptoTesting.cpp, base10multiplicationTest()";
    
        uint32_t src1[4];
        uint32_t src2[4];
        uint32_t dest1[4];
        int ret;
    
        src1[3]=0;  src1[2]=0;  src1[1]=0;  src1[0]=0;
        src2[3]=0;  src2[2]=0;  src2[1]=0;  src2[0]=0;

		//0*0
		ret=_baseType->multiplication(src1,src2,dest1,4);
        if(_baseType->compare(src1,dest1,4)!=0 || !ret)
            throw os::smart_ptr<std::exception>(new generalTestException("0*0 failed!",locString),shared_type);

		//0*1
		src2[0]=1;
		ret=_baseType->multiplication(src1,src2,dest1,4);
        if(_baseType->compare(src1,dest1,4)!=0 || !ret)
            throw os::smart_ptr<std::exception>(new generalTestException("0*1 failed!",locString),shared_type);

		//2*1
		src2[0]=1;
		src1[0]=2;
		ret=_baseType->multiplication(src1,src2,dest1,4);
        if(_baseType->compare(src1,dest1,4)!=0 || !ret)
            throw os::smart_ptr<std::exception>(new generalTestException("2*1 failed!",locString),shared_type);

		//2*0:0:1:1
		src2[1]=1;
		ret=_baseType->multiplication(src1,src2,dest1,4);
		src1[1]=2;
        if(_baseType->compare(src1,dest1,4)!=0 || !ret)
            throw os::smart_ptr<std::exception>(new generalTestException("2*0:0:1:1 failed!",locString),shared_type);

		//Carry test
		src1[1]=0;
		src2[0]=1<<31;
		ret=_baseType->multiplication(src1,src2,dest1,4);
		src1[0]=0;
		src1[1]=3;
        if(_baseType->compare(src1,dest1,4)!=0 || !ret)
            throw os::smart_ptr<std::exception>(new generalTestException("Carry failed!",locString),shared_type);

		//Overflow test
		src2[3]=1<<30;
		ret=_baseType->multiplication(src1,src2,dest1,4);
		if(ret)
			throw os::smart_ptr<std::exception>(new generalTestException("Overflow 1 failed!",locString),shared_type);
		ret=_baseType->multiplication(src2,src1,dest1,4);
		if(ret)
			throw os::smart_ptr<std::exception>(new generalTestException("Overflow 2 failed!",locString),shared_type);
    }
    //Division test
    void base10divisionTest() throw(os::smart_ptr<std::exception>)
    {
        struct numberType* _baseType = typeCheckBase10();
        std::string locString = "c_cryptoTesting.cpp, base10divisionTest()";
    
        uint32_t src1[4];
        uint32_t src2[4];
        uint32_t dest1[4];
        int ret;
    
        src1[3]=0;  src1[2]=0;  src1[1]=0;  src1[0]=0;
        src2[3]=0;  src2[2]=0;  src2[1]=0;  src2[0]=0;

		//0/0
		ret=_baseType->division(src1,src2,dest1,4);
        if(_baseType->compare(src1,dest1,4)!=0 || ret)
            throw os::smart_ptr<std::exception>(new generalTestException("0/0 failed!",locString),shared_type);

		//0/1
		src2[0]=1;
		ret=_baseType->division(src1,src2,dest1,4);
        if(_baseType->compare(src1,dest1,4)!=0 || !ret)
            throw os::smart_ptr<std::exception>(new generalTestException("0/1 failed!",locString),shared_type);

		//1/1
		src1[0]=1;
		ret=_baseType->division(src1,src2,dest1,4);
        if(_baseType->compare(src1,dest1,4)!=0 || !ret)
            throw os::smart_ptr<std::exception>(new generalTestException("1/1 failed!",locString),shared_type);

		//2/1
		src1[0]=2;
		ret=_baseType->division(src1,src2,dest1,4);
        if(_baseType->compare(src1,dest1,4)!=0 || !ret)
            throw os::smart_ptr<std::exception>(new generalTestException("2/1 failed!",locString),shared_type);

		//5/2
		src1[0]=5;
		src2[0]=2;
		ret=_baseType->division(src1,src2,dest1,4);
		src1[0]=2;
        if(_baseType->compare(src1,dest1,4)!=0 || !ret)
            throw os::smart_ptr<std::exception>(new generalTestException("5/2 failed!",locString),shared_type);

		//5/3
		src1[0]=5;
		src2[0]=3;
		ret=_baseType->division(src1,src2,dest1,4);
		src1[0]=1;
        if(_baseType->compare(src1,dest1,4)!=0 || !ret)
            throw os::smart_ptr<std::exception>(new generalTestException("5/3 failed!",locString),shared_type);

		//0:0:2:2/2
		src1[0]=2;
		src1[1]=2;
		src2[0]=2;
		ret=_baseType->division(src1,src2,dest1,4);
		src1[0]=1;
		src1[1]=1;
        if(_baseType->compare(src1,dest1,4)!=0 || !ret)
            throw os::smart_ptr<std::exception>(new generalTestException("0:0:2:2/2 failed!",locString),shared_type);

		//0:0:2:2/0:0:1:1
		src1[0]=2;
		src1[1]=2;
		src2[0]=1;
		src2[1]=1;
		ret=_baseType->division(src1,src2,dest1,4);
		src1[0]=2;
		src1[1]=0;
        if(_baseType->compare(src1,dest1,4)!=0 || !ret)
            throw os::smart_ptr<std::exception>(new generalTestException("0:0:2:2/0:0:1:1 failed!",locString),shared_type);
    }
	//Modulo
	void base10moduloTest() throw(os::smart_ptr<std::exception>)
	{
		struct numberType* _baseType = typeCheckBase10();
        std::string locString = "c_cryptoTesting.cpp, base10moduloTest()";
    
        uint32_t src1[4];
        uint32_t src2[4];
        uint32_t dest1[4];
        int ret;
    
        src1[3]=0;  src1[2]=0;  src1[1]=0;  src1[0]=0;
        src2[3]=0;  src2[2]=0;  src2[1]=0;  src2[0]=0;

		//0%0
		ret=_baseType->modulo(src1,src2,dest1,4);
        if(_baseType->compare(src1,dest1,4)!=0 || ret)
            throw os::smart_ptr<std::exception>(new generalTestException("0%0 failed!",locString),shared_type);

		//0%2
		src1[0]=0;
		src2[0]=2;
		ret=_baseType->modulo(src1,src2,dest1,4);
        if(_baseType->compare(src1,dest1,4)!=0 || !ret)
            throw os::smart_ptr<std::exception>(new generalTestException("0%2 failed!",locString),shared_type);

		//1%2
		src1[0]=1;
		src2[0]=2;
		ret=_baseType->modulo(src1,src2,dest1,4);
        if(_baseType->compare(src1,dest1,4)!=0 || !ret)
            throw os::smart_ptr<std::exception>(new generalTestException("1%2 failed!",locString),shared_type);

		//2%2
		src1[0]=2;
		src2[0]=2;
		ret=_baseType->modulo(src1,src2,dest1,4);
		src1[0]=0;
        if(_baseType->compare(src1,dest1,4)!=0 || !ret)
            throw os::smart_ptr<std::exception>(new generalTestException("2%2 failed!",locString),shared_type);

		//3%2
		src1[0]=3;
		src2[0]=2;
		ret=_baseType->modulo(src1,src2,dest1,4);
		src1[0]=1;
        if(_baseType->compare(src1,dest1,4)!=0 || !ret)
            throw os::smart_ptr<std::exception>(new generalTestException("3%2 failed!",locString),shared_type);
        //3%7
        src1[0]=3;
        src2[0]=7;
        ret=_baseType->modulo(src1,src2,dest1,4);
        src1[0]=3;
        if(_baseType->compare(src1,dest1,4)!=0 || !ret)
            throw os::smart_ptr<std::exception>(new generalTestException("3%2 failed!",locString),shared_type);

		//0:0:1:3%0:0:1:0
		src1[1]=1;
		src1[0]=3;
		src2[1]=1;
		src2[0]=0;
		ret=_baseType->modulo(src1,src2,dest1,4);
		src1[1]=0;
        if(_baseType->compare(src1,dest1,4)!=0 || !ret)
            throw os::smart_ptr<std::exception>(new generalTestException("0:0:1:3%0:0:1:0 failed!",locString),shared_type);

	}
	//Base 10 exponentiation
	void base10exponentiationTest() throw(os::smart_ptr<std::exception>)
	{
		struct numberType* _baseType = typeCheckBase10();
        std::string locString = "c_cryptoTesting.cpp, base10exponentiationTest()";
    
        uint32_t src1[4];
        uint32_t src2[4];
        uint32_t dest1[4];
        int ret;
    
        src1[3]=0;  src1[2]=0;  src1[1]=0;  src1[0]=0;
        src2[3]=0;  src2[2]=0;  src2[1]=0;  src2[0]=0;

		//0^0
		ret=_baseType->exponentiation(src1,src2,dest1,4);
        if(_baseType->compare(src1,dest1,4)!=0 || !ret)
            throw os::smart_ptr<std::exception>(new generalTestException("0^0 failed!",locString),shared_type);

		//0^1
		src2[0]=1;
		ret=_baseType->exponentiation(src1,src2,dest1,4);
        if(_baseType->compare(src1,dest1,4)!=0 || !ret)
            throw os::smart_ptr<std::exception>(new generalTestException("0^1 failed!",locString),shared_type);

		//1^0
		src1[0]=1;
		src2[0]=1;
		ret=_baseType->exponentiation(src1,src2,dest1,4);
        if(_baseType->compare(src1,dest1,4)!=0 || !ret)
            throw os::smart_ptr<std::exception>(new generalTestException("1^0 failed!",locString),shared_type);

		//1^2
		src1[0]=1;
		src2[0]=2;
		ret=_baseType->exponentiation(src1,src2,dest1,4);
        if(_baseType->compare(src1,dest1,4)!=0 || !ret)
            throw os::smart_ptr<std::exception>(new generalTestException("1^2 failed!",locString),shared_type);

		//2^1
		src1[0]=2;
		src2[0]=1;
		ret=_baseType->exponentiation(src1,src2,dest1,4);
        if(_baseType->compare(src1,dest1,4)!=0 || !ret)
            throw os::smart_ptr<std::exception>(new generalTestException("2^1 failed!",locString),shared_type);

		//2^2
		src1[0]=2;
		src2[0]=2;
		ret=_baseType->exponentiation(src1,src2,dest1,4);
		src1[0]=4;
        if(_baseType->compare(src1,dest1,4)!=0 || !ret)
            throw os::smart_ptr<std::exception>(new generalTestException("2^2 failed!",locString),shared_type);

		//2^3
		src1[0]=2;
		src2[0]=3;
		ret=_baseType->exponentiation(src1,src2,dest1,4);
		src1[0]=8;
        if(_baseType->compare(src1,dest1,4)!=0 || !ret)
            throw os::smart_ptr<std::exception>(new generalTestException("2^2 failed!",locString),shared_type);

		//3^2
		src1[0]=3;
		src2[0]=2;
		ret=_baseType->exponentiation(src1,src2,dest1,4);
		src1[0]=9;
        if(_baseType->compare(src1,dest1,4)!=0 || !ret)
            throw os::smart_ptr<std::exception>(new generalTestException("3^2 failed!",locString),shared_type);

		//3^3
		src1[0]=3;
		src2[0]=3;
		ret=_baseType->exponentiation(src1,src2,dest1,4);
		src1[0]=27;
        if(_baseType->compare(src1,dest1,4)!=0 || !ret)
            throw os::smart_ptr<std::exception>(new generalTestException("3^3 failed!",locString),shared_type);

		//0:0:1:0^2
		src1[0]=0;
		src1[1]=1;
		src2[0]=2;
		ret=_baseType->exponentiation(src1,src2,dest1,4);
		src1[1]=0;
		src1[2]=1;
        if(_baseType->compare(src1,dest1,4)!=0 || !ret)
            throw os::smart_ptr<std::exception>(new generalTestException("0:0:1:0^2 failed!",locString),shared_type);

		//0:0:1:0^3
		src1[0]=0;
		src1[1]=1;
		src1[2]=0;
		src2[0]=3;
		ret=_baseType->exponentiation(src1,src2,dest1,4);
		src1[1]=0;
		src1[3]=1;
        if(_baseType->compare(src1,dest1,4)!=0 || !ret)
            throw os::smart_ptr<std::exception>(new generalTestException("0:0:1:0^3 failed!",locString),shared_type);

		//0:0:1:0^4
		src1[0]=0;
		src1[1]=1;
		src1[2]=0;
		src1[3]=0;

		src2[0]=4;
		ret=_baseType->exponentiation(src1,src2,dest1,4);
        if(ret)
            throw os::smart_ptr<std::exception>(new generalTestException("Overflow failed!",locString),shared_type);
	}
	//Base 10 modular exponentiation
	void base10modularExponentiationTest() throw(os::smart_ptr<std::exception>)
	{
		struct numberType* _baseType = typeCheckBase10();
        std::string locString = "c_cryptoTesting.cpp, base10modularExponentiationTest()";
    
        uint32_t src1[4];
        uint32_t src2[4];
		uint32_t modVal[4];
        uint32_t dest1[4];
        int ret;
    
        src1[3]=0;  src1[2]=0;  src1[1]=0;  src1[0]=0;
        src2[3]=0;  src2[2]=0;  src2[1]=0;  src2[0]=0;
		modVal[3]=0;  modVal[2]=1;  modVal[1]=0;  modVal[0]=1;

		//0^0
		ret=_baseType->moduloExponentiation(src1,src2,modVal,dest1,4);
        if(_baseType->compare(src1,dest1,4)!=0 || !ret)
            throw os::smart_ptr<std::exception>(new generalTestException("0^0 failed!",locString),shared_type);

		//0^1
		src2[0]=1;
		ret=_baseType->moduloExponentiation(src1,src2,modVal,dest1,4);
        if(_baseType->compare(src1,dest1,4)!=0 || !ret)
            throw os::smart_ptr<std::exception>(new generalTestException("0^1 failed!",locString),shared_type);

		//1^0
		src1[0]=1;
		src2[0]=1;
		ret=_baseType->moduloExponentiation(src1,src2,modVal,dest1,4);
        if(_baseType->compare(src1,dest1,4)!=0 || !ret)
            throw os::smart_ptr<std::exception>(new generalTestException("1^0 failed!",locString),shared_type);

		//1^2
		src1[0]=1;
		src2[0]=2;
		ret=_baseType->moduloExponentiation(src1,src2,modVal,dest1,4);
        if(_baseType->compare(src1,dest1,4)!=0 || !ret)
            throw os::smart_ptr<std::exception>(new generalTestException("1^2 failed!",locString),shared_type);

		//2^1
		src1[0]=2;
		src2[0]=1;
		ret=_baseType->moduloExponentiation(src1,src2,modVal,dest1,4);
        if(_baseType->compare(src1,dest1,4)!=0 || !ret)
            throw os::smart_ptr<std::exception>(new generalTestException("2^1 failed!",locString),shared_type);

		//2^2
		src1[0]=2;
		src2[0]=2;
		ret=_baseType->moduloExponentiation(src1,src2,modVal,dest1,4);
		src1[0]=4;
        if(_baseType->compare(src1,dest1,4)!=0 || !ret)
            throw os::smart_ptr<std::exception>(new generalTestException("2^2 failed!",locString),shared_type);

		//2^3
		src1[0]=2;
		src2[0]=3;
		ret=_baseType->moduloExponentiation(src1,src2,modVal,dest1,4);
		src1[0]=8;
        if(_baseType->compare(src1,dest1,4)!=0 || !ret)
            throw os::smart_ptr<std::exception>(new generalTestException("2^2 failed!",locString),shared_type);

		//3^2
		src1[0]=3;
		src2[0]=2;
		ret=_baseType->moduloExponentiation(src1,src2,modVal,dest1,4);
		src1[0]=9;
        if(_baseType->compare(src1,dest1,4)!=0 || !ret)
            throw os::smart_ptr<std::exception>(new generalTestException("3^2 failed!",locString),shared_type);

		//3^3
		src1[0]=3;
		src2[0]=3;
		ret=_baseType->moduloExponentiation(src1,src2,modVal,dest1,4);
		src1[0]=27;
        if(_baseType->compare(src1,dest1,4)!=0 || !ret)
            throw os::smart_ptr<std::exception>(new generalTestException("3^3 failed!",locString),shared_type);

		//0:0:1:0^2
		src1[0]=0;
		src1[1]=1;
		src2[0]=2;
		ret=_baseType->moduloExponentiation(src1,src2,modVal,dest1,4);
		src1[1]=0;
		src1[2]=1;
        if(_baseType->compare(src1,dest1,4)!=0 || !ret)
            throw os::smart_ptr<std::exception>(new generalTestException("0:0:1:0^2 failed!",locString),shared_type);

		//0:0:1:0^3
		src1[0]=0;
		src1[1]=1;
		src1[2]=0;
		src2[0]=3;
		ret=_baseType->moduloExponentiation(src1,src2,modVal,dest1,4);
		//testout<<dest1[3]<<":"<<dest1[2]<<":"<<dest1[1]<<":"<<dest1[0]<<std::endl;
		src1[0]=1;
		src1[1]=4294967295;
		src1[2]=0;
        if(_baseType->compare(src1,dest1,4)!=0 || !ret)
            throw os::smart_ptr<std::exception>(new generalTestException("0:0:1:0^3 failed!",locString),shared_type);

		//0:0:1:0^4
		src1[0]=0;
		src1[1]=1;
		src1[2]=0;
		src1[3]=0;

		src2[0]=4;
		ret=_baseType->moduloExponentiation(src1,src2,modVal,dest1,4);
        if(ret)
            throw os::smart_ptr<std::exception>(new generalTestException("Overflow failed!",locString),shared_type);
	}
	//Base 10 GCD test
	void base10GCDTest() throw(os::smart_ptr<std::exception>)
	{
		struct numberType* _baseType = typeCheckBase10();
        std::string locString = "c_cryptoTesting.cpp, base10GCDTest()";

		uint32_t src1[4];
        uint32_t src2[4];
        uint32_t dest1[4];
        int ret;
    
        src1[3]=0;  src1[2]=0;  src1[1]=0;  src1[0]=0;
        src2[3]=0;  src2[2]=0;  src2[1]=0;  src2[0]=0;

		//0 gcd 0
		ret=_baseType->gcd(src1,src2,dest1,4);
        if(_baseType->compare(src1,dest1,4)!=0 || !ret)
            throw os::smart_ptr<std::exception>(new generalTestException("0 gcd 0 failed!",locString),shared_type);

		//1 gcd 1
		src1[0]=1;
		src2[0]=1;
		ret=_baseType->gcd(src1,src2,dest1,4);
        if(_baseType->compare(src1,dest1,4)!=0 || !ret)
            throw os::smart_ptr<std::exception>(new generalTestException("1 gcd 1 failed!",locString),shared_type);

		//2 gcd 4
		src1[0]=2;
		src2[0]=4;
		ret=_baseType->gcd(src1,src2,dest1,4);
        if(_baseType->compare(src1,dest1,4)!=0 || !ret)
            throw os::smart_ptr<std::exception>(new generalTestException("2 gcd 4 failed!",locString),shared_type);

		//4 gcd 6
		src1[0]=4;
		src2[0]=6;
		ret=_baseType->gcd(src1,src2,dest1,4);
		src1[0]=2;
        if(_baseType->compare(src1,dest1,4)!=0 || !ret)
            throw os::smart_ptr<std::exception>(new generalTestException("4 gcd 6 failed!",locString),shared_type);

		//6 gcd 9
		src1[0]=6;
		src2[0]=9;
		ret=_baseType->gcd(src1,src2,dest1,4);
		src1[0]=3;
        if(_baseType->compare(src1,dest1,4)!=0 || !ret)
            throw os::smart_ptr<std::exception>(new generalTestException("6 gcd 9 failed!",locString),shared_type);

		//9 gcd 6
		src1[0]=9;
		src2[0]=6;
		ret=_baseType->gcd(src1,src2,dest1,4);
		src1[0]=3;
        if(_baseType->compare(src1,dest1,4)!=0 || !ret)
            throw os::smart_ptr<std::exception>(new generalTestException("9 gcd 6 failed!",locString),shared_type);

		//9 gcd 6
		src1[0]=9;
		src2[0]=6;
		ret=_baseType->gcd(src1,src2,dest1,4);
		src1[0]=3;
        if(_baseType->compare(src1,dest1,4)!=0 || !ret)
            throw os::smart_ptr<std::exception>(new generalTestException("9 gcd 6 failed!",locString),shared_type);
	}
	//Base 10 Modular Inverse Test
	void base10ModularInverseTest() throw(os::smart_ptr<std::exception>)
	{
		struct numberType* _baseType = typeCheckBase10();
        std::string locString = "c_cryptoTesting.cpp, base10ModularInverseTest()";

		uint32_t src1[4];
        uint32_t src2[4];
        uint32_t dest1[4];
        int ret;
    
        src1[3]=0;  src1[2]=0;  src1[1]=0;  src1[0]=0;
        src2[3]=0;  src2[2]=0;  src2[1]=0;  src2[0]=0;

		//(3 mod 7)^-1
		src1[0]=3;
		src2[0]=7;
		ret=_baseType->modInverse(src1,src2,dest1,4);
		src1[0]=5;
		if(_baseType->compare(src1,dest1,4)!=0 || !ret)
            throw os::smart_ptr<std::exception>(new generalTestException("(3 mod 7)^-1 failed!",locString),shared_type);

		//(4 mod 97)^-1
		src1[0]=4;
		src2[0]=97;
		ret=_baseType->modInverse(src1,src2,dest1,4);
		src1[0]=73;
		if(_baseType->compare(src1,dest1,4)!=0 || !ret)
            throw os::smart_ptr<std::exception>(new generalTestException("(4 mod 97)^-1 failed!",locString),shared_type);

		//(300 mod 38897)^-1
		src1[0]=300;
		src2[0]=38897;
		ret=_baseType->modInverse(src1,src2,dest1,4);
		src1[0]=8687;
		if(_baseType->compare(src1,dest1,4)!=0 || !ret)
            throw os::smart_ptr<std::exception>(new generalTestException("(300 mod 38897)^-1 failed!",locString),shared_type);

		//(6 mod 8)^-1
		src1[0]=6;
		src2[0]=8;
		ret=_baseType->modInverse(src1,src2,dest1,4);
		src1[0]=1;
		if(_baseType->compare(src1,dest1,4)!=0 || ret)
            throw os::smart_ptr<std::exception>(new generalTestException("(6 mod 8)^-1 failed!",locString),shared_type);
	}
	//Base 10 Primality test
	void base10PrimealityTest() throw(os::smart_ptr<std::exception>)
	{
		struct numberType* _baseType = typeCheckBase10();
        std::string locString = "c_cryptoTesting.cpp, base10PrimealityTest()";
	
		uint32_t src1[4];
    
        src1[3]=0;  src1[2]=0;  src1[1]=0;  src1[0]=0;

		//0
		if(primeTest(src1,10,4))
			throw os::smart_ptr<std::exception>(new generalTestException("0 is not prime!",locString),shared_type);

		//1
		src1[0]=1;
		if(!primeTest(src1,10,4))
			throw os::smart_ptr<std::exception>(new generalTestException("1 is prime!",locString),shared_type);

		//2
		src1[0]=2;
		if(!primeTest(src1,10,4))
			throw os::smart_ptr<std::exception>(new generalTestException("2 is prime!",locString),shared_type);

		//3
		src1[0]=3;
		if(!primeTest(src1,10,4))
			throw os::smart_ptr<std::exception>(new generalTestException("3 is prime!",locString),shared_type);

		//4
		src1[0]=4;
		if(primeTest(src1,10,4))
			throw os::smart_ptr<std::exception>(new generalTestException("4 is not prime!",locString),shared_type);

		//5
		src1[0]=5;
		if(!primeTest(src1,10,4))
			throw os::smart_ptr<std::exception>(new generalTestException("5 is prime!",locString),shared_type);

		//55
		src1[0]=55;
		if(primeTest(src1,10,4))
			throw os::smart_ptr<std::exception>(new generalTestException("55 is not prime!",locString),shared_type);

		//99
		src1[0]=99;
		if(primeTest(src1,10,4))
			throw os::smart_ptr<std::exception>(new generalTestException("99 is not prime!",locString),shared_type);

		//401
		src1[0]=401;
		if(!primeTest(src1,10,4))
			throw os::smart_ptr<std::exception>(new generalTestException("401 is prime!",locString),shared_type);

		//243407
		src1[0]=243407;
		if(primeTest(src1,10,4))
			throw os::smart_ptr<std::exception>(new generalTestException("243407 is not prime!",locString),shared_type);
	}

/*================================================================
	C Test Suites
 ================================================================*/

    //C Base-10 Test Suite
    C_BaseTenSuite::C_BaseTenSuite():
        testSuite("C Base-10")
    {
        pushTest("NULL Number Type",&nullNumberType);
        pushTest("Base-10 Number Type",&typeCheckBase10Test);
        pushTest("Compare",&base10compareTest);
        pushTest("Addition",&base10additionTest);
        pushTest("Subtraction",&base10subtractionTest);
        pushTest("Right Shift",&base10rightShiftTest);
        pushTest("Left Shift",&base10leftShiftTest);
        pushTest("Multiplication",&base10multiplicationTest);
        pushTest("Division",&base10divisionTest);
		pushTest("Modulo",&base10moduloTest);
		pushTest("Exponentiation",&base10exponentiationTest);
		pushTest("Modular Exponentiation",&base10modularExponentiationTest);
		pushTest("GCD",&base10GCDTest);
		pushTest("Modular Inverse",&base10ModularInverseTest);
		pushTest("Prime Testing",&base10PrimealityTest);
    }

#endif

///@endcond
//Primary author: Jonathan Bedard
//Confirmed working: 11/29/2015

#ifndef C_CRYPTO_TESTING_CPP
#define C_CRYPTO_TESTING_CPP

#include "c_cryptoTesting.h"
#include <string>

using namespace test;
using namespace os;

    //Confirms NULL value
    void nullNumberType() throw(os::smart_ptr<std::exception>)
    {
        std::string locString = "c_cryptoTesting.cpp, nullNumberType()";
        struct numberType* _nullType = buildNullNumberType();
        if(_nullType == NULL) throw os::smart_ptr<std::exception>(new generalTestException("NULL type could not be built!",locString),shared_type);
        
        if(_nullType->typeID != 0) throw os::smart_ptr<std::exception>(new generalTestException("NULL type ID wrong!",locString),shared_type);
        if(std::string(_nullType->name) != std::string("NULL Type")) throw os::smart_ptr<std::exception>(new generalTestException("NULL type name wrong!",locString),shared_type);
        
        if(_nullType->compare != NULL) throw os::smart_ptr<std::exception>(new generalTestException("NULL type compare defined!!",locString),shared_type);
        
        if(_nullType->addition != NULL) throw os::smart_ptr<std::exception>(new generalTestException("NULL type addition defined!!",locString),shared_type);
        if(_nullType->subtraction != NULL) throw os::smart_ptr<std::exception>(new generalTestException("NULL type subtraction defined!!",locString),shared_type);
        
        if(_nullType->rightShift != NULL) throw os::smart_ptr<std::exception>(new generalTestException("NULL type right shift defined!!",locString),shared_type);
        if(_nullType->leftShift != NULL) throw os::smart_ptr<std::exception>(new generalTestException("NULL type left shift defined!!",locString),shared_type);
        
        if(_nullType->multiplication != NULL) throw os::smart_ptr<std::exception>(new generalTestException("NULL type multiplication defined!!",locString),shared_type);
        if(_nullType->division != NULL) throw os::smart_ptr<std::exception>(new generalTestException("NULL type division defined!!",locString),shared_type);
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
        
        if(_baseType->typeID != 1)
        {
            if(errorType) throw os::smart_ptr<std::exception>(new generalTestException("Base-10 type ID wrong!",locString),shared_type);
            else throw defThrow;
        }
        if(std::string(_baseType->name) != std::string("Base 10 Type"))
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
            if(errorType) throw os::smart_ptr<std::exception>(new generalTestException("NULL type multiplication defined!!",locString),shared_type);
            else throw defThrow;
        }
        if(_baseType->division == NULL)
        {
            if(errorType) throw os::smart_ptr<std::exception>(new generalTestException("NULL type division defined!!",locString),shared_type);
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
    //Right shift test
    void base10rightShiftTest() throw(os::smart_ptr<std::exception>)
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
        ret = _baseType->rightShift(src1,1,dest1,4);
        if(_baseType->compare(src2,dest1,4)!=0 || !ret)
            throw os::smart_ptr<std::exception>(new generalTestException("1<<1 failed!",locString),shared_type);
        
        //1<<32
        src1[0]=1;
        src2[0]=0;
        src2[1]=1;
        ret = _baseType->rightShift(src1,32,dest1,4);
        if(_baseType->compare(src2,dest1,4)!=0 || !ret)
            throw os::smart_ptr<std::exception>(new generalTestException("1<<32 failed!",locString),shared_type);
        
        //1<<33
        src1[0]=1;
        src2[1]=2;
        ret = _baseType->rightShift(src1,33,dest1,4);
        if(_baseType->compare(src2,dest1,4)!=0 || !ret)
            throw os::smart_ptr<std::exception>(new generalTestException("1<<33 failed!",locString),shared_type);
        
        //Split Shift
        src1[0]=1|(1<<31);
        src2[0]=0;
        src2[1]=2;
        src2[2]=1;
        ret = _baseType->rightShift(src1,33,dest1,4);
        if(_baseType->compare(src2,dest1,4)!=0 || !ret)
            throw os::smart_ptr<std::exception>(new generalTestException("Split shift failed!",locString),shared_type);
        
        //Split Shift 2
        src1[0]=1|(1<<31);
        src2[0]=0;
        src2[1]=0;
        src2[2]=2;
        src2[3]=1;
        ret = _baseType->rightShift(src1,65,dest1,4);
        if(_baseType->compare(src2,dest1,4)!=0 || !ret)
            throw os::smart_ptr<std::exception>(new generalTestException("Split shift 2 failed!",locString),shared_type);
        
        //Overflow (a little)
        ret = _baseType->rightShift(src1,97,dest1,4);
        if(ret)
            throw os::smart_ptr<std::exception>(new generalTestException("Overflow (a little) failed!",locString),shared_type);
        
        //Overflow (a lot)
        src1[0]=0;
        src1[1]=1;
        ret = _baseType->rightShift(src1,129,dest1,4);
        if(ret)
            throw os::smart_ptr<std::exception>(new generalTestException("Overflow (a lot) failed!",locString),shared_type);
        
    }
    //Left shift test
    void base10leftShiftTest() throw(os::smart_ptr<std::exception>)
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
        ret = _baseType->leftShift(src1,1,dest1,4);
        if(_baseType->compare(src2,dest1,4)!=0 || !ret)
            throw os::smart_ptr<std::exception>(new generalTestException("1>>1 failed!",locString),shared_type);
        
        //2>>1
        src1[0]=2;
        src2[0]=1;
        ret = _baseType->leftShift(src1,1,dest1,4);
        if(_baseType->compare(src2,dest1,4)!=0 || !ret)
            throw os::smart_ptr<std::exception>(new generalTestException("2>>1 failed!",locString),shared_type);
        
        //0:0:1:0>>32
        src1[0]=0;
        src1[1]=1;
        ret = _baseType->leftShift(src1,32,dest1,4);
        if(_baseType->compare(src2,dest1,4)!=0 || !ret)
            throw os::smart_ptr<std::exception>(new generalTestException("0:0:1:0>>32 failed!",locString),shared_type);
        
        //0:0:1:0>>31
        src1[0]=0;
        src1[1]=1;
        src2[0]=2;
        ret = _baseType->leftShift(src1,31,dest1,4);
        if(_baseType->compare(src2,dest1,4)!=0 || !ret)
            throw os::smart_ptr<std::exception>(new generalTestException("0:0:1:0>>31 failed!",locString),shared_type);
        
        //0:3:0:0>>33
        src1[0]=0;
        src1[1]=0;
        src1[2]=3;
        src2[0]=1<<31;
        src2[1]=1;
        ret = _baseType->leftShift(src1,33,dest1,4);
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
        uint32_t dest2[4];
        int ret;
    
        src1[3]=0;  src1[2]=0;  src1[1]=0;  src1[0]=0;
        src2[3]=0;  src2[2]=0;  src2[1]=0;  src2[0]=0;
    }
    //Division test
    void base10divisionTest() throw(os::smart_ptr<std::exception>)
    {
        struct numberType* _baseType = typeCheckBase10();
        std::string locString = "c_cryptoTesting.cpp, base10divisionTest()";
    
        uint32_t src1[4];
        uint32_t src2[4];
        uint32_t dest1[4];
        uint32_t dest2[4];
        int ret;
    
        src1[3]=0;  src1[2]=0;  src1[1]=0;  src1[0]=0;
        src2[3]=0;  src2[2]=0;  src2[1]=0;  src2[0]=0;
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
        pushTest("Multiplicaiton",&base10multiplicationTest);
        pushTest("Division",&base10divisionTest);
    }

#endif
//Primary author: Jonathan Bedard
//Confirmed working: 11/28/2015

#ifndef C_BASE_TEN_C
#define C_BASE_TEN_C

#include "c_BaseTen.h"

#ifdef __cplusplus
extern "C" {
#endif
    
    static bool baseTenInit = false;
    static struct numberType _baseTen;
    
    //Returns the definition of a base Ten number
    struct numberType* buildBaseTenType()
    {
        if(baseTenInit) return &_baseTen;
        
        _baseTen.typeID = 1;
        _baseTen.name = "Base 10 Type";
        
        _baseTen.compare = &standardCompare;
        
        _baseTen.addition = &base10Addition;
        _baseTen.subtraction = &base10Subtraction;
        
        _baseTen.rightShift = &standardRightShift;
        _baseTen.leftShift = &standardLeftShift;
        
        _baseTen.multiplication = base10Multiplication;
        _baseTen.division = base10Division;
        
        baseTenInit = true;
        return &_baseTen;
    }
    
    //Addition
    int base10Addition(uint32_t* src1, uint32_t* src2, uint32_t* dest, uint16_t length)
    {
        //Zero return is error
        if(length<=0) return 0;
        
        //Zero target
        for(int cnt = 0;cnt<length;cnt++)
            dest[cnt]=0;
        
        //Add to target
        uint64_t carry = 0;
        for(int cnt =0;cnt<length;cnt++)
        {
            uint64_t tm = (uint64_t) src1[cnt] + (uint64_t) src2[cnt] +carry;
            dest[cnt]+=(uint32_t)tm;
            
            if(tm != (uint32_t) tm)
                carry = (uint32_t) (tm>>32);
            else
                carry=0;
        }
        if(carry>0) return 0;
        
        return 1;
    }
    //Subtraction
    int base10Subtraction(uint32_t* src1, uint32_t* src2, uint32_t* dest, uint16_t length)
    {
        //Zero return is error
        if(length<=0) return 0;
        
        //Zero target
        for(int cnt = 0;cnt<length;cnt++)
            dest[cnt]=0;
        
        //Subtract src2 from src1 (src1-src2)
        uint64_t borrow = 0;
        for(int cnt=0;cnt<length;cnt++)
        {
            dest[cnt] = src1[cnt] - (src2[cnt]+borrow);
            if((uint64_t)src1[cnt]>=(uint64_t)src2[cnt]+borrow)
                borrow = 0;
            else
                borrow = 1;
        }
        if(borrow>0) return 0;
        return 1;
    }
    //Multiplication
    int base10Multiplication(uint32_t* src1, uint32_t* src2, uint32_t* dest, uint16_t length)
    {
        if(length<=0) return 0;
        return 1;
    }
    //Division
    int base10Division(uint32_t* src1, uint32_t* src2, uint32_t* dest, uint16_t length)
    {
        if(length<=0) return 0;
        return 1;
    }

#ifdef __cplusplus
}
#endif

#endif
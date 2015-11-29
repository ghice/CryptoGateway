//Primary author: Jonathan Bedard
//Confirmed working: 11/28/2015

#ifndef C_BASE_TEN_H
#define C_BASE_TEN_H

#include "c_numberDefinitions.h"

#ifdef __cplusplus
extern "C" {
#endif

    struct numberType* buildBaseTenType();

    int base10Addition(uint32_t* src1, uint32_t* src2, uint32_t* dest, uint16_t length);
    int base10Subtraction(uint32_t* src1, uint32_t* src2, uint32_t* dest, uint16_t length);
    int base10Multiplication(uint32_t* src1, uint32_t* src2, uint32_t* dest, uint16_t length);
    int base10Division(uint32_t* src1, uint32_t* src2, uint32_t* dest, uint16_t length);
    
#ifdef __cplusplus
}
#endif

#endif
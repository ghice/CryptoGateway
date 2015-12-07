//Primary author: Jonathan Bedard
//Confirmed working: 12/6/2015

#ifndef C_BASE_TEN_H
#define C_BASE_TEN_H

#include "c_numberDefinitions.h"

#ifdef __cplusplus
extern "C" {
#endif
	#include <time.h>

    struct numberType* buildBaseTenType();

    int base10Addition(uint32_t* src1, uint32_t* src2, uint32_t* dest, uint16_t length);
    int base10Subtraction(uint32_t* src1, uint32_t* src2, uint32_t* dest, uint16_t length);

    int base10Multiplication(uint32_t* src1, uint32_t* src2, uint32_t* dest, uint16_t length);
    int base10Division(uint32_t* src1, uint32_t* src2, uint32_t* dest, uint16_t length);
    int base10Modulo(uint32_t* src1, uint32_t* src2, uint32_t* dest, uint16_t length);

	int base10Exponentiation(uint32_t* src1, uint32_t* src2, uint32_t* dest, uint16_t length);
	int base10ModuloExponentiation(uint32_t* src1, uint32_t* src2, uint32_t* src3, uint32_t* dest, uint16_t length);

	int base10GCD(uint32_t* src1, uint32_t* src2, uint32_t* dest, uint16_t length);
	int base10ModInverse(uint32_t* src1, uint32_t* src2, uint32_t* dest, uint16_t length);

	int primeTest(uint32_t* src1, uint16_t test_iteration, uint16_t length);

#ifdef __cplusplus
}
#endif

#endif
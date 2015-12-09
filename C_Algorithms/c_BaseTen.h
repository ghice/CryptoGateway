//Primary author: Jonathan Bedard
//Confirmed working: 12/8/2015

#ifndef C_BASE_TEN_H
#define C_BASE_TEN_H

#include "c_numberDefinitions.h"

#ifdef __cplusplus
extern "C" {
#endif
	#include <time.h>

    struct numberType* buildBaseTenType();

    int base10Addition(const uint32_t* src1, const uint32_t* src2, uint32_t* dest, uint16_t length);
    int base10Subtraction(const uint32_t* src1, const uint32_t* src2, uint32_t* dest, uint16_t length);

    int base10Multiplication(const uint32_t* src1, const uint32_t* src2, uint32_t* dest, uint16_t length);
    int base10Division(const uint32_t* src1, const uint32_t* src2, uint32_t* dest, uint16_t length);
    int base10Modulo(const uint32_t* src1, const uint32_t* src2, uint32_t* dest, uint16_t length);

	int base10Exponentiation(const uint32_t* src1, const uint32_t* src2, uint32_t* dest, uint16_t length);
	int base10ModuloExponentiation(const uint32_t* src1, const uint32_t* src2, const uint32_t* src3, uint32_t* dest, uint16_t length);

	int base10GCD(const uint32_t* src1, const uint32_t* src2, uint32_t* dest, uint16_t length);
	int base10ModInverse(const uint32_t* src1, const uint32_t* src2, uint32_t* dest, uint16_t length);

	int primeTest(const uint32_t* src1, uint16_t test_iteration, uint16_t length);

#ifdef __cplusplus
}
#endif

#endif
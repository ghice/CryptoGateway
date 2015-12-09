//Primary author: Jonathan Bedard
//Confirmed working: 12/8/2015

#ifndef C_NUMBER_DEFINITIONS_H
#define C_NUMBER_DEFINITIONS_H

#ifdef __cplusplus
extern "C" {
#endif
	#include "cryptoCConstants.h"

    #include <stdio.h>
    #include <stdint.h>
	#include <stdlib.h>
	#include <string.h>
    
    //Typedef for operator function
    typedef int (*operatorFunction)(const uint32_t*,const uint32_t*,uint32_t*,uint16_t);
	typedef int (*tripleCalculation)(const uint32_t*,const uint32_t*,const uint32_t*,uint32_t*,uint16_t);
    typedef int (*shiftFunction)(const uint32_t*,uint16_t,uint32_t*,uint16_t);
    typedef int (*compareFunction)(const uint32_t*,const uint32_t*,uint16_t);
    
    //Number type struct
    struct numberType
    {
        //Number meta-data
        int typeID;
        const char* name;
        
        compareFunction compare;
        
        operatorFunction addition;
        operatorFunction subtraction;
        
        shiftFunction rightShift;
        shiftFunction leftShift;
        
        operatorFunction multiplication;
        operatorFunction division;
		operatorFunction modulo;

		operatorFunction exponentiation;
		tripleCalculation moduloExponentiation;

		operatorFunction gcd;
		operatorFunction modInverse;
    };

    struct numberType* buildNullNumberType();
    int standardCompare(const uint32_t* src1, const uint32_t* src2, uint16_t length);
    int standardRightShift(const uint32_t* src1, uint16_t src2, uint32_t* dest, uint16_t length);
    int standardLeftShift(const uint32_t* src1, uint16_t src2, uint32_t* dest, uint16_t length);

#ifdef __cplusplus
}
#endif

#endif
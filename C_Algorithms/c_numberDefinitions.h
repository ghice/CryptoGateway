//Primary author: Jonathan Bedard
//Confirmed working: 11/29/2015

#ifndef C_NUMBER_DEFINITIONS_H
#define C_NUMBER_DEFINITIONS_H

#ifdef __cplusplus
extern "C" {
#endif
    
    #include <stdio.h>
    #include <stdint.h>
    
    //Typedef for operator function
    typedef int (*operatorFunction)(uint32_t*,uint32_t*,uint32_t*,uint16_t);
    typedef int (*shiftFunction)(uint32_t*,uint16_t,uint32_t*,uint16_t);
    typedef int (*compareFunction)(uint32_t*,uint32_t*,uint16_t);
    
    //Number type struct
    struct numberType
    {
        //Number meta-data
        int typeID;
        char* name;
        
        compareFunction compare;
        
        operatorFunction addition;
        operatorFunction subtraction;
        
        shiftFunction rightShift;
        shiftFunction leftShift;
        
        operatorFunction multiplication;
        operatorFunction division;
    };

    struct numberType* buildNullNumberType();
    int standardCompare(uint32_t* src1, uint32_t* src2, uint16_t length);
    int standardRightShift(uint32_t* src1, uint16_t src2, uint32_t* dest, uint16_t length);
    int standardLeftShift(uint32_t* src1, uint16_t src2, uint32_t* dest, uint16_t length);

#ifdef __cplusplus
}
#endif

#endif
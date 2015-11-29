//Primary author: Jonathan Bedard
//Confirmed working: 11/28/2015

#ifndef C_NUMBER_DEFINITIONS_C
#define C_NUMBER_DEFINITIONS_C

#include "c_numberDefinitions.h"

#ifdef __cplusplus
extern "C" {
#endif
    
    static bool nullInit = false;
    static struct numberType _nullType;

    //Returns a null type
    struct numberType* buildNullNumberType()
    {
        if(nullInit) return &_nullType;
        
        _nullType.typeID = 0;
        _nullType.name = "NULL Type";
        
        _nullType.compare = NULL;
        
        _nullType.addition = NULL;
        _nullType.subtraction = NULL;
        
        nullInit = true;
        return &_nullType;
    }
    //Standard compare function
    int standardCompare(uint32_t* src1, uint32_t* src2, uint16_t length)
    {
        for(int cnt=length-1;cnt>=0;cnt--)
        {
            if(src1[cnt]>src2[cnt])
                return 1;
            else if(src1[cnt]<src2[cnt])
                return -1;
        }
        return 0;
    }
    
#ifdef __cplusplus
}
#endif

#endif
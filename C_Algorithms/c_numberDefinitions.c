//Primary author: Jonathan Bedard
//Confirmed working: 11/30/2015

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
        
        _nullType.rightShift = NULL;
        _nullType.leftShift = NULL;
        
        _nullType.multiplication = NULL;
        _nullType.division = NULL;
		_nullType.modulo = NULL;
        
		_nullType.exponentiation = NULL;
		_nullType.moduloExponentiation = NULL;

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
    //Standard right shift function
    int standardRightShift(uint32_t* src1, uint16_t src2, uint32_t* dest, uint16_t length)
    {
		if(length<=0) return 0;
        
		uint32_t* targ = (uint32_t*) malloc(length*sizeof(uint32_t));
        uint16_t bigShift=src2/32;
        uint16_t smallShift=src2%32;
        
        //Set to zero
        int cnt=0;
        for(cnt=0;cnt<length;cnt++)
            targ[cnt]=0;
        if(bigShift>=length)
		{
			for(int cnt=0;cnt<length;cnt++)
			dest[cnt]=targ[cnt];
			free(targ);
            return 1;
		}
        
        uint32_t carry=src1[bigShift]>>smallShift;
        for(cnt=bigShift+1;cnt<length;cnt++)
        {
            if(smallShift>0)
                targ[cnt-bigShift-1]=carry|src1[cnt]<<(32-smallShift);
            else
                targ[cnt-bigShift-1]=carry;
            carry=src1[cnt]>>smallShift;
        }
		for(int cnt=0;cnt<length;cnt++)
			dest[cnt]=targ[cnt];
		free(targ);
        return 1;
    }
    //Standard left shift function
    int standardLeftShift(uint32_t* src1, uint16_t src2, uint32_t* dest, uint16_t length)
    {
        if(length<=0) return 0;
        
        //Set to zero
		uint32_t* targ = (uint32_t*) malloc(length*sizeof(uint32_t));
        int cnt=0;
        for(cnt=0;cnt<length;cnt++)
            targ[cnt]=0;
        
		
        uint16_t bigShift=src2/32;
        uint16_t smallShift=src2%32;
        uint32_t oldVal = 0;
        
        for(cnt=0;cnt+bigShift<length;cnt++)
        {
            if(smallShift>0)
            {
                targ[cnt+bigShift]=oldVal | (src1[cnt]<<smallShift);
                oldVal = src1[cnt]>>(32-smallShift);
            }
            else
                targ[cnt+bigShift]=src1[cnt];
        }

		for(int cnt=0;cnt<length;cnt++)
			dest[cnt]=targ[cnt];
		free(targ);
        if(oldVal>0) return 0;
        
        for(;cnt<length;cnt++)
        {
            if(src1[cnt]>0)
                return 0;
        }
        return 1;
    }
    
#ifdef __cplusplus
}
#endif

#endif
//Primary author: Jonathan Bedard
//Confirmed working: 11/30/2015

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
        
        _baseTen.multiplication = &base10Multiplication;
        _baseTen.division = &base10Division;
		_baseTen.modulo = &base10Modulo;
        
		_baseTen.exponentiation = base10Exponentiation;
		_baseTen.moduloExponentiation = base10ModuloExponentiation;

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
        
        //Subtract src2 from src1 (src1-src2)
        uint64_t borrow = 0;
        for(int cnt=0;cnt<length;cnt++)
        {
            uint32_t t = src1[cnt] - (src2[cnt]+borrow);
            if((uint64_t)src1[cnt]>=(uint64_t)src2[cnt]+borrow)
                borrow = 0;
            else
                borrow = 1;
			dest[cnt]=t;
        }
        if(borrow>0) return 0;
        return 1;
    }
    //Multiplication
    int base10Multiplication(uint32_t* src1, uint32_t* src2, uint32_t* dest, uint16_t length)
    {
        if(length<=0) return 0;

		int ret = 1;
		uint32_t* temp = (uint32_t*) malloc(length*sizeof(uint32_t));
		uint32_t* targ = (uint32_t*) malloc(length*sizeof(uint32_t));

		//Zero the target
		for(int cnt =0;cnt<length;cnt++)
			targ[cnt]=0;
		
		//Preform multiplication
		for(int cnt=0;cnt<length*32;cnt++)
		{
			int bigPos=cnt/32;
			int smallPos=cnt%32;
			if(src1[bigPos]&(1<<smallPos))
			{
				if(!standardLeftShift(src2,cnt,temp,length))
					ret = 0;
				if(!base10Addition(targ,temp,targ,length))
					ret = 0;
			}
		}

		for(int cnt=0;cnt<length;cnt++)
			dest[cnt]=targ[cnt];
		free(targ);
		free(temp);
        return ret;
    }
    //Division
    int base10Division(uint32_t* src1, uint32_t* src2, uint32_t* dest, uint16_t length)
    {
        if(length<=0) return 0;

		//Exit if divide by zero
		int found = 0;
		for(int cnt=0;cnt<length && !found;cnt++)
		{
			if(src2[cnt]!=0)
				found = 1;
		}

		//Zero the target
		uint32_t* targ = (uint32_t*) malloc(length*sizeof(uint32_t));
		for(int cnt =0;cnt<length;cnt++)
			targ[cnt]=0;

		if(!found)
		{
			for(int cnt=0;cnt<length;cnt++)
				dest[cnt]=targ[cnt];
			free(targ);
			return 0;
		}

		uint32_t* temp1 = (uint32_t*) malloc(length*sizeof(uint32_t));
		uint32_t* temp2 = (uint32_t*) malloc(length*sizeof(uint32_t));
		
		//Set temp1 to current src1
		for(int cnt =0;cnt<length;cnt++)
			temp1[cnt]=src1[cnt];

		//Find starting position of src1
		int src1_pos=length*32-1;
		found = 0;
		while(src1_pos>=0 && !found)
		{
			if(src1[src1_pos/32] & (1<<(src1_pos%32)))
				found = 1;
			src1_pos--;
		}

		//Find starting position of src2
		int src2_pos=length*32-1;
		found = 0;
		while(src2_pos>=0 && !found)
		{
			if(src2[src2_pos/32] & (1<<(src2_pos%32)))
				found = 1;
			src2_pos--;
		}

		//Found the two starting positions, calculate division
		for(int cnt=src1_pos-src2_pos;cnt>=0;cnt--)
		{
			//Preform shift
			if(!standardLeftShift(src2,cnt,temp2,length))
			{
				//Shouldn't ever get here
				free(temp1);
				free(temp2);
				for(int cnt=0;cnt<length;cnt++)
					dest[cnt]=targ[cnt];
				free(targ);
				return 0;
			}

			//If temp1>=temp2, subtract and bind to output
			if(standardCompare(temp1,temp2,length)>=0)
			{
				targ[cnt/32]=targ[cnt/32] | (1<<(cnt%32));
				base10Subtraction(temp1,temp2,temp1,length);
				
			}
		}

		free(temp1);
		free(temp2);

		for(int cnt=0;cnt<length;cnt++)
			dest[cnt]=targ[cnt];
		free(targ);
        return 1;
    }
	//Modulo
	int base10Modulo(uint32_t* src1, uint32_t* src2, uint32_t* dest, uint16_t length)
	{
		if(length<=0) return 0;

		//Exit if divide by zero
		int found = 0;
		for(int cnt=0;cnt<length && !found;cnt++)
		{
			if(src2[cnt]!=0)
				found = 1;
		}

		if(!found)
		{
			//Zero the target
			for(int cnt =0;cnt<length;cnt++)
				dest[cnt]=0;
			return 0;
		}

		uint32_t* temp1 = (uint32_t*) malloc(length*sizeof(uint32_t));
		uint32_t* temp2 = (uint32_t*) malloc(length*sizeof(uint32_t));
		
		//Set temp1 to current src1
		for(int cnt =0;cnt<length;cnt++)
			temp1[cnt]=src1[cnt];

		//Find starting position of src1
		int src1_pos=length*32-1;
		found = 0;
		while(src1_pos>=0 && !found)
		{
			if(src1[src1_pos/32] & (1<<(src1_pos%32)))
				found = 1;
			src1_pos--;
		}

		//Find starting position of src2
		int src2_pos=length*32-1;
		found = 0;
		while(src2_pos>=0 && !found)
		{
			if(src2[src2_pos/32] & (1<<(src2_pos%32)))
				found = 1;
			src2_pos--;
		}

		//Found the two starting positions, calculate division
		for(int cnt=src1_pos-src2_pos;cnt>=0;cnt--)
		{
			//Preform shift
			if(!standardLeftShift(src2,cnt,temp2,length))
			{
				//Shouldn't ever get here
				free(temp1);
				free(temp2);
				return 0;
			}

			//If temp1>=temp2, subtract and bind to output
			if(standardCompare(temp1,temp2,length)>=0)
				base10Subtraction(temp1,temp2,temp1,length);
		}

		//Copy from temp into destination
		for(int cnt=0;cnt<length;cnt++)
			dest[cnt] = temp1[cnt];

		free(temp1);
		free(temp2);
        return 1;
	}
	//Exponentiation
	int base10Exponentiation(uint32_t* src1, uint32_t* src2, uint32_t* dest, uint16_t length)
	{
		 //Zero return is error
        if(length<=0) return 0;

		uint32_t* temp1 = (uint32_t*) malloc(length*sizeof(uint32_t));
		uint32_t* temp2 = (uint32_t*) malloc(length*sizeof(uint32_t));

		free(temp1);
		free(temp2);

		return 1;
	}
	//Modulo exponentiation
	int base10ModuloExponentiation(uint32_t* src1, uint32_t* src2, uint32_t* dest, uint16_t length)
	{
		 //Zero return is error
        if(length<=0) return 0;

		uint32_t* temp1 = (uint32_t*) malloc(length*sizeof(uint32_t));
		uint32_t* temp2 = (uint32_t*) malloc(length*sizeof(uint32_t));

		free(temp1);
		free(temp2);

		return 1;
	}

#ifdef __cplusplus
}
#endif

#endif
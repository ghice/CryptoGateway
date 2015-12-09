//Primary author: Jonathan Bedard
//Confirmed working: 12/9/2015

#ifndef CRYPTO_NUMBER_CPP
#define CRYPTO_NUMBER_CPP

#include "cryptoLogging.h"
#include "cryptoNumber.h"

using namespace crypto;

/*================================================================
	Number
 ================================================================*/

    //Default constructor
    number::number(struct numberType* numDef)
    {
        _numDef=numDef;
        _size = 1;
        _data = new uint32_t[1];
        _data[0]=0;
    }
    //Size constructor
    number::number(uint16_t size, struct numberType* numDef)
    {
        _numDef=numDef;
        _size=size;
        if(_size<1)_size=0;
        
        _data = new uint32_t[_size];
        memset(_data,0,sizeof(uint32_t)*_size);
    }
    //Construct with data
    number::number(uint32_t* d, uint16_t size, struct numberType* numDef)
    {
        _numDef=numDef;
        _size=size;
        if(_size<1)_size=0;
        
        _data = new uint32_t[_size];
        if(size<1)
            memset(_data,0,sizeof(uint32_t)*_size);
        else
            memcpy(_data, d, sizeof(uint32_t)*_size);
    }
    //Copy constructor
    number::number(const number& num)
    {
        _numDef=num._numDef;
        _size=num._size;
        _data = new uint32_t[_size];
        memcpy(_data, num._data, sizeof(uint32_t)*_size);
    }
	//Copy number into self
	number& number::operator=(const number& num)
	{
		if(&num!=this)
		{
			delete [] _data;
			_numDef=num._numDef;
			_size=num._size;
			_data = new uint32_t[_size];
			memcpy(_data, num._data, sizeof(uint32_t)*_size);
		}
		return *this;
	}
    //Destructor
    number::~number(){delete [] _data;}

//Size manipulation----------------------------------------------

    //Reduce the size of a number
    void number::reduce()
    {
        uint32_t targ_size = _size;
        for(targ_size=_size;targ_size>0 && _data[targ_size]==0;targ_size--){}
        
        targ_size++;
        if(targ_size==_size) return;
        
        uint32_t* temp = new uint32_t[targ_size];
        memcpy(temp, _data, sizeof(uint32_t)*targ_size);
        delete [] _data;
        _data =temp;
        _size = targ_size;
    }
    //Expand the size of a number
    void number::expand(uint16_t size)
    {
        //Check size first
        if(size<_size)
        {
            cryptoerr<<"Cannot expand!  Target size is smaller than current size!"<<std::endl;
            return;
        }
        if(size==_size) return;
        
        //Preform expansion
        uint32_t* temp = new uint32_t[size];
        memset(temp,0,sizeof(uint32_t)*size);
        memcpy(temp, _data, sizeof(uint32_t)*_size);
        delete [] _data;
        _data =temp;
        _size = size;
    }

//To and from string---------------------------------------------

    //isHex char
    static bool isHexCharacter(char c)
    {
        switch (c)
        {
            case '0':
            case '1':
            case '2':
            case '3':
            case '4':
            case '5':
            case '6':
            case '7':
            case '8':
            case '9':
            case 'A':
            case 'B':
            case 'C':
            case 'D':
            case 'E':
            case 'F':
                return true;
            default:
                break;
        }
        return false;
    }
    //Converts a uint32 to hex
    static std::string toHex(uint32_t i)
    {
        std::string ret="";
        for(int cnt=0;cnt<8;cnt++)
        {
            uint16_t temp=i&15;
            switch (temp)
            {
                case 0:
                    ret='0'+ret;
                    break;
                case 1:
                    ret='1'+ret;
                    break;
                case 2:
                    ret='2'+ret;
                    break;
                case 3:
                    ret='3'+ret;
                    break;
                case 4:
                    ret='4'+ret;
                    break;
                case 5:
                    ret='5'+ret;
                    break;
                case 6:
                    ret='6'+ret;
                    break;
                case 7:
                    ret='7'+ret;
                    break;
                case 8:
                    ret='8'+ret;
                    break;
                case 9:
                    ret='9'+ret;
                    break;
                case 10:
                    ret='A'+ret;
                    break;
                case 11:
                    ret='B'+ret;
                    break;
                case 12:
                    ret='C'+ret;
                    break;
                case 13:
                    ret='D'+ret;
                    break;
                case 14:
                    ret='E'+ret;
                    break;
                case 15:
                    ret='F'+ret;
                    break;
                default:
                    cryptoerr<<"Hex conversion failed!"<<std::endl;
                    return ret;
            }
            i=i>>4;
        }
        return ret;
    }
    //Converts a hex value to a uint32_t
    static uint32_t fromHex(const std::string& str)
    {
        uint32_t ret=0;
        
        for(int i=0;i<str.length();i++)
        {
            ret = ret<<4;
            switch (str[i])
            {
                case '0':
                    break;
                case '1':
                    ret=ret|1;
                    break;
                case '2':
                    ret=ret|2;
                    break;
                case '3':
                    ret=ret|3;
                    break;
                case '4':
                    ret=ret|4;
                    break;
                case '5':
                    ret=ret|5;
                    break;
                case '6':
                    ret=ret|6;
                    break;
                case '7':
                    ret=ret|7;
                    break;
                case '8':
                    ret=ret|8;
                    break;
                case '9':
                    ret=ret|9;
                    break;
                case 'A':
                    ret=ret|10;
                    break;
                case 'B':
                    ret=ret|11;
                    break;
                case 'C':
                    ret=ret|12;
                    break;
                case 'D':
                    ret=ret|13;
                    break;
                case 'E':
                    ret=ret|14;
                    break;
                case 'F':
                    ret=ret|15;
                    break;
                defult:
                    break;
            }
        }
        return ret;
    }
    //Converts number to string
    std::string number::toString() const
    {
        std::string ret="";
        for(int i=0;i<_size;i++)
        {
            ret=toHex(_data[i])+ret;
            if(i+1<_size)
                ret=':'+ret;
        }
        return ret;
    }
    //Converts string to number
    void number::fromString(const std::string& str)
    {
        //Reset everything
        _size=1;
        delete [] _data;
        uint16_t totLen=1;
        int groupLen=0;
        
        //Try and determine length
        for(int i=0;i<str.length();i++)
        {
            //Its a hex character
            if(isHexCharacter(str[i]))
            {
                groupLen++;
                if(groupLen>8)
                {
                    cryptoerr<<"Illegal number construction string!"<<std::endl;
                    _data=new uint32_t[_size];
                    memset(_data,0,sizeof(uint32_t)*_size);
                    return;
                }
            }
            //Its a divider
            else if(str[i]==':')
            {
                totLen++;
                groupLen=0;
            }
            //Its neither, illegal string
            else
            {
                cryptoerr<<"Illegal number construction string!"<<std::endl;
                _data=new uint32_t[_size];
                memset(_data,0,sizeof(uint32_t)*_size);
                return;
            }
        }
        
        //Build target array
        _size=totLen;
        _data=new uint32_t[_size];
        memset(_data,0,sizeof(uint32_t)*_size);
        int strTrace = 0;
        for(uint16_t trc=_size;trc>0 && strTrace<str.length();trc--)
        {
            std::string current="";
            for(;strTrace<str.length() && str[strTrace]!=':';strTrace++)
                current+=str[strTrace];
            strTrace++;
            _data[trc-1]=fromHex(current);
        }
    }
    //Ostream operator
    std::ostream& crypto::operator<<(std::ostream& os, const number& num)
    {
        os<<num.toString();
        return os;
    }
    //Istream operator
    std::istream& crypto::operator>>(std::istream& is, number& num)
    {
        std::string track="";
        char cur=is.get();
        int charCount=0;
        while(charCount<8 && (cur==':' || isHexCharacter(cur)))
        {
            if(cur==':') charCount=0;
            track+=cur;
            cur=is.get();
        }
        num.fromString(track);
        return is;
    }

//Operator Access------------------------------------------------

	//Return element at position
	uint32_t number::operator[](uint16_t pos) const
	{
		if(pos>_size) return 0;
		return _data[pos];
	}
	//Modify element at position
	uint32_t& number::operator[](uint16_t pos)
	{
		if(pos>_size)
		{
			cryptoerr<<"Position "<<pos<<" is outside of the bounds of size "<<_size<<"!"<<std::endl;
			return _data[0];
		}
		return _data[pos];
	}

//Comparison functions-------------------------------------------

    //Compare two numbers
    int number::compare(const number& num) const
    {
        uint16_t comp_len=_size;
        
        //Size mis-matches
        if(_size>num._size)
        {
            comp_len=num._size;
            for(uint16_t trc=_size;trc>comp_len;trc--)
            {
                if(_data[trc-1]>0) return 1;
            }
        }
        else if(_size<num._size)
        {
            for(uint16_t trc=num._size;trc>comp_len;trc--)
            {
                if(num._data[trc-1]>0) return -1;
            }
        }
        
        //Matched size
        for(uint16_t trc=comp_len;trc>0;trc--)
        {
            if(_data[trc-1]>num._data[trc-1]) return 1;
            else if(_data[trc-1]<num._data[trc-1]) return -1;
        }
        return 0;
    }
    //Equality operator
    const bool number::operator==(const number& comp) const {return compare(comp)==0;}
    //Not equal operator
    const bool number::operator!=(const number& comp) const {return compare(comp)!=0;}
    //Less than or equal
    const bool number::operator<=(const number& comp) const {return compare(comp)!=1;}
    //Greater than or equal
    const bool number::operator>=(const number& comp) const {return compare(comp)!=-1;}
    //Less than
    const bool number::operator<(const number& comp) const {return compare(comp)==-1;}
    //Greater than
    const bool number::operator>(const number& comp) const {return compare(comp)==1;}

/*================================================================
	Number
 ================================================================*/

    //Basic integer constructor
    integer::integer():number(buildBaseTenType()){}
    //Size constructor
    integer::integer(uint16_t size):number(size,buildBaseTenType()){}
    //Data constructor
    integer::integer(uint32_t* d, uint16_t size):number(d,size,buildBaseTenType()){}
    //Copy constructor
    integer::integer(const integer& num):number(num){}

#endif
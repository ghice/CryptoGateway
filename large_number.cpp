//Primary author: Jonathan Bedard
//Certified working 2/14/2015

#ifndef LARGE_NUMBER_CPP
#define LARGE_NUMBER_CPP

//For debug
#include <string>
#include <iostream>
#include <stdlib.h>

#include "large_number.h"
#include "security_gateway.h"

using namespace std;

//Constructors----------------------------------------------------------
  //Default large_number constructor
  large_number::large_number()
  {
    int cnt = 0;
    
    while(cnt<LARGE_NUMBER_SIZE)
    {
      data[cnt] = 0;
      cnt++;
    }
  }
  //Initializes the number based off of an array
  large_number::large_number(uint32_t* array, int length)
  {
    int cnt = 0;

    while(cnt<LARGE_NUMBER_SIZE&&cnt<length)
    {
      data[cnt] = array[cnt];
      cnt++;
    }
    while(cnt<LARGE_NUMBER_SIZE)
    {
      data[cnt] = 0;
      cnt++;
    }
  }
  //Copy constructor
  large_number::large_number(const large_number& source)
  {
    int cnt = 0;

    while(cnt<LARGE_NUMBER_SIZE)
    {
      data[cnt] = source.data[cnt];
      cnt++;
    }
  }
  //Deletion
  large_number::~large_number()
  {
  }
  bool large_number::push_array(uint32_t* array, int length)
  {
    int cnt = 0;

    while(cnt<LARGE_NUMBER_SIZE&&cnt<length)
    {
      data[cnt] = array[cnt];
      cnt++;
    }
    while(cnt<LARGE_NUMBER_SIZE)
    {
      data[cnt] = 0;
      cnt++;
    }
	return true;
  }
  bool large_number::push_array_comp_mode(uint32_t* array, int length)
  {
	int cnt = 0;

    while(cnt<LARGE_NUMBER_SIZE&&cnt<length)
    {
      data[cnt] = from_comp_mode_sgtw(array[cnt]);
      cnt++;
    }
    while(cnt<LARGE_NUMBER_SIZE)
    {
      data[cnt] = 0;
      cnt++;
    }
	return true;
  }
//Opperators-----------------------------------------------------------

  //Adds two large_numbers
  const large_number large_number::add(const large_number& add) const
  {
    large_number ret;
    bool carry = false;
    int cnt = 0;
    
    while(cnt<LARGE_NUMBER_SIZE)
    {
      ret.data[cnt] = data[cnt]+add.data[cnt];
      if(carry)
      {
	ret.data[cnt] = ret.data[cnt]+1;
	if(ret.data[cnt]<=data[cnt] || ret.data[cnt]<=add.data[cnt])
	  carry = true;
	else
	  carry = false;
      }
      else
      {
	if(ret.data[cnt]<data[cnt] || ret.data[cnt]<add.data[cnt])
	  carry = true;
	else
	  carry = false;
      }
	
      cnt++;
    }
    return ret;
  }
  //Subtracts one large_number from another
  const large_number large_number::subtract(const large_number& add) const
  {
    large_number ret;
    
    bool carry = false;
    int cnt = 0;
    
    while(cnt<LARGE_NUMBER_SIZE)
    {
      ret.data[cnt] = data[cnt]-add.data[cnt];
      if(carry)
      {
	ret.data[cnt] = ret.data[cnt]-1;
	if(ret.data[cnt]>=data[cnt])
	  carry = true;
	else
	  carry = false;
      }
      else
      {
	if(ret.data[cnt]>data[cnt])
	  carry = true;
	else
	  carry = false;
      }
	
      cnt++;
    }
    return ret;
  }
  //Shifts the number left x bits
  const large_number large_number::leftShift(int x) const
  {
    large_number ret;
    
    //Test the "perfect" case
    if(x%32 == 0)
    {
      int cnt = 0;
      
      while(((x+1)>>5)+cnt<LARGE_NUMBER_SIZE)
      {
	ret.data[((x+1)>>5)+cnt]=data[cnt];
	cnt++;
      }
      return ret;
    }
    
    //Else
    int cnt = 0;
    while(((x>>5)+cnt)<LARGE_NUMBER_SIZE)
    {
      ret.data[((x>>5)+cnt)]=ret.data[((x>>5)+cnt)]|(data[cnt]<<(x%32));
      if(((x>>5)+1+cnt)<LARGE_NUMBER_SIZE)
	ret.data[((x>>5)+(cnt+1))]=data[cnt]>>(32-(x%32));
      cnt++;
    }

    return ret;
  }
  //Shifts the number right x bits
  const large_number large_number::rightShift(int x) const
  {
    large_number ret;
    
    //Test the "perfect" case
    if(x%32 == 0)
    {
      int cnt = ((x+1)>>5);
      
      while(cnt<LARGE_NUMBER_SIZE)
      {
	ret.data[cnt-((x+1)>>5)]=data[cnt];
	cnt++;
      }
      return ret;
    }
    
    //Else
    int cnt = x>>5;
    while(cnt<LARGE_NUMBER_SIZE)
    {
      ret.data[cnt-(x>>5)]=data[cnt]>>(x%32);
      if((cnt+1)<LARGE_NUMBER_SIZE)
	ret.data[cnt-(x>>5)]=ret.data[cnt-(x>>5)]|data[cnt+1]<<(32-(x%32));
      cnt++;
    }
    
    return ret;
  }
  //Multiplies two large_numbers
  const large_number large_number::multiply(const large_number& multi) const
  {
    large_number ret;
    int cnt = 0;
    
    while(cnt<LARGE_NUMBER_SIZE*32)
    {
      if(multi.getBit(cnt))
	ret = ret.add(leftShift(cnt));
      cnt++;
    }
    
    return ret;
  }
  //Preforms modulo
  const large_number large_number::mod(const large_number& mod) const
  {
    large_number comp;
    
    //Test for zero case
    if(comp.compare(mod) == 0)
      return comp;
    
    large_number ret(*this);
    
    int len = 0;
    int cnt = 0;
    
    //Find length of mod comparator
    while(cnt<LARGE_NUMBER_SIZE*32)
    {
      if(mod.getBit(cnt))
	len = cnt;
      cnt++;
    }
    
    cnt = 32*LARGE_NUMBER_SIZE-len-1;
    int temp;
    
    while(cnt>=0)
    {
      large_number subHold(mod.leftShift(cnt));
      
      if(ret.compare(subHold)!=-1)
	ret = ret.subtract(subHold);
      cnt--;
    }
    
    return ret;
  }
  //Preforms modulo
  const large_number large_number::divide(const large_number& div) const
  {
    large_number comp;
    
    //Test for zero case
    if(comp.compare(div) == 0)
      return comp;
    
    large_number ret(*this);
    large_number return_div;
    
    uint32_t array[1];
    array[0] = 1;
    large_number one(array,1);
    
    //Test if div is larger than this
    if(ret.compare(div) == -1)
      return comp;
    
    int len = 0;
    int cnt = 0;
    
    //Find length of mod comparator
    while(cnt<LARGE_NUMBER_SIZE*32)
    {
      if(div.getBit(cnt))
	len = cnt;
      cnt++;
    }
    
    cnt = 32*LARGE_NUMBER_SIZE-len-1;
    int temp;
    
    while(cnt>=0)
    {
      large_number subHold(div.leftShift(cnt));
      
      if(ret.compare(subHold)!=-1)
      {
	return_div = return_div.add(one.leftShift(cnt));
	ret = ret.subtract(subHold);
      }
      cnt--;
    }
    
    return return_div;
  }
  //gcd
  const large_number large_number::gcd(const large_number& mod) const
  {
    large_number a(*this);
    large_number b(mod);
    large_number t;
    large_number zero;
    while(b.compare(zero)!=0)
    {
      t = b;
      b = a.mod(b);
      a = t;
    }
    return a;
  }
  //Modular inverse
  const large_number large_number::mod_inverse(const large_number& mod) const
  {
    large_number one;
    large_number zero;
    uint32_t array[1];
    array[0] = 1;
    one.push_array(array, 1);
    
    if(this->gcd(mod).compare(one)!=0)
    {
      cerr<<"Impossible to preform modular inverse!"<<endl;
      cerr<<"GCD is not one"<<endl;
      return one;
    }
    
    large_number t;
    large_number r = mod;
    large_number newt = one;
    large_number newr(*this);
    
    large_number quotient;
    large_number hld;
    large_number temp;
    
    while(newr.compare(zero)!=0)
    {
      quotient = r.divide(newr);

      temp = newt;
      hld = quotient.multiply(newt).mod(mod);
      if(t.compare(hld)==-1)
	t = t.add(mod);
      newt = t.subtract(hld);
      t = temp;
      
      temp = newr;
      hld = quotient.multiply(newr).mod(mod);
      if(r.compare(hld)==-1)
	r = r.add(mod);
      newr = r.subtract(hld);
      r = temp;
      
      t = t.mod(mod);
    }
    
    if(r.compare(one)==1)
    {
      cerr<<"There is no modular inverse!"<<endl;
      return one;
    }
    
    return t;
  }
  //Preforms modular exponentiation
  const large_number large_number::modExpo(const large_number& pow, const large_number& mod) const
  {
    uint32_t array[1];
    array[0] = 1;
    large_number ret(array, 1);
    
    large_number trace(*this);
    int cnt = 0;
    
    while(cnt<LARGE_NUMBER_SIZE*32)
    {
      if(pow.getBit(cnt))
      {
	/*ret.printHex();
	cout<<endl;
	trace.printHex();
	cout<<endl<<endl;*/
	
	ret = ret.multiply(trace);
	ret = ret.mod(mod);
      }
      trace = trace.multiply(trace);
      trace = trace.mod(mod);
      cnt++;
    }
    
    return ret;
  }
  //Tests if a long numbwer is prime
  bool large_number::isPrime() const
  {
    int trace = 1;
    bool flag = false;
    
    //Check for zero set
    while(!flag && trace<LARGE_NUMBER_SIZE)
    {
      if(data[trace]!=0)
	flag = true;
      trace++;
    }
    
    //Check 0th element
    if(!flag)
    {
      if(data[0] == 0)
	return false;
      if(data[0] == 1)
	return true;
      if(data[0]==2)
	return true;
      if(data[0]==3)
	return true;
    }
    
    //Check for even case
    if(getBit(0)==false)
      return false;
    
    //Miller-Rabin Test
    uint32_t hldArray[LARGE_NUMBER_SIZE];
    hldArray[0] = 1;
    large_number one(hldArray, 1);
    large_number minusOne(subtract(one));
    //Find "d"
    trace = 0;
    flag = false;
    
    while(!flag)
    {
      trace++;
      if(minusOne.getBit(trace))
	flag = true;
    }
    large_number d = minusOne.rightShift(trace);
    int s = trace;
    int cnt = 0;
    
    large_number test;
    //Preform the test
    while(cnt<PRIME_TEST_ITERATION)
    {
      if(cnt==0)
	test = one.add(one);
      else if(cnt == 1)
	test = test.add(one);
      else
      {
	//Randomly select a test number
	trace=LARGE_NUMBER_SIZE;
	flag = false;
	
	while(trace>0)
	{
	  trace--;
	  if(flag)
	    hldArray[trace] = rand()^(rand()<<1);
	  else
	    hldArray[trace] = 0;
	  if(data[trace]!=0&&!flag)
	  {
	    flag = true;
	    hldArray[trace] = (rand()^(rand()<<1))%data[trace];
	  }
	}
	if(hldArray[0]<3)
	  hldArray[0] = 3;
	test = large_integer(hldArray, LARGE_NUMBER_SIZE);
	
      }
      large_number x = test.modExpo(d,*this);
    
      if(x!=one&&x!=minusOne)
      {
	flag = false;
	trace = 1;
	while(trace<s&&!flag)
	{
	  x = x.multiply(x);
	  x = x.mod(*this);
	  
	  if(x==one)
	    return false;
	  if(x==minusOne)
	    flag = true;
	  
	  trace++;
	}
	
	if(!flag)
	  return false;
	}
      cnt++;
      }
      return true;
    }
  
//Accessor Functions----------------------------------------------------
  
  //Returns the status of a bit
  bool large_number::getBit(int bitLoc) const
  {
    return data[bitLoc>>5]&(1<<(bitLoc%32));
  }
  //Allows for access of inner indecies
  uint32_t large_number::getArrayNumber(int index) const
  {
    if(index>=0&&index<LARGE_NUMBER_SIZE)
      return data[index];
    return 0;
  }
  //Compares two large_numbers (< is -1, = is 0 and > is 1)
   const int large_number::compare(const large_number& comp) const
   {
     int cnt = LARGE_NUMBER_SIZE-1;
     while(cnt>=0)
     {
       if(data[cnt]>comp.data[cnt])
	 return 1;
       else if(data[cnt]<comp.data[cnt])
	 return -1;
       cnt--;
     }
     return 0;
   }
  
//Printing Functions----------------------------------------------------
  
  //Prints the hex of the number
  void large_number::printHex() const
  {
    int cnt = LARGE_NUMBER_SIZE-1;
    while(cnt>=0)
    {
      cout<<hex<<data[cnt];
      cnt--;
      if(cnt>=0)
	cout<<":";
    }
  }
  //Prints the binary of the number
  void large_number::printBinary() const
  {
    int cnt = LARGE_NUMBER_SIZE*32-1;
    
    while(cnt>=0)
    {
      if(getBit(cnt))
	cout<<1;
      else
	cout<<0;
      
      if(cnt%32==0&&cnt-1>0)
	cout<<" : ";
      
      cnt--;
    }
  }
  //The ostrem operator
  std::ostream& operator<<(std::ostream& os, const large_number& obj)
  {
    int cnt = LARGE_NUMBER_SIZE-1;
    
    while(cnt>=0)
    {
      os<<dec<<obj.data[cnt];
      cnt--;
      if(cnt>=0)
	os<<":";
    }
    return os;
  }
  
//Operators------------------------------------------------------------

  //Equallity Operator
  const large_number& large_number::operator=(const large_number& equ)
  {
    int cnt = 0;
    
    while(cnt<LARGE_NUMBER_SIZE)
    {
      data[cnt] = equ.data[cnt];
      cnt++;
    }
    
    return *this;
  }
  const bool large_number::operator<(const large_number& comp) const
  {
    return (compare(comp)==-1);
  }
  const bool large_number::operator>(const large_number& comp) const
  {
    return (compare(comp)==1);
  }
  const bool large_number::operator<=(const large_number& comp) const
  {
    return (compare(comp)!=1);
  }
  const bool large_number::operator>=(const large_number& comp) const
  {
    return (compare(comp)!=-1);
  }
  const bool large_number::operator==(const large_number& comp) const
  {
    return (compare(comp)==0);
  }
  const bool large_number::operator!=(const large_number& comp) const
  {
    return (compare(comp)!=0);
  }

//large_integer-----------------------------------------------------------------

//Constructors----------------------------------------------------------

  //Default constructor
  large_integer::large_integer()
  {
    int cnt = 0;
    
    while(cnt<LARGE_NUMBER_SIZE)
    {
      data[cnt] = 0;
      cnt++;
    }
  }
   //Array constructor
  large_integer::large_integer(uint32_t* array, int length)
  {
    int cnt = 0;

    while(cnt<LARGE_NUMBER_SIZE&&cnt<length)
    {
      data[cnt] = array[cnt];
      cnt++;
    }
    while(cnt<LARGE_NUMBER_SIZE)
    {
      data[cnt] = 0;
      cnt++;
    }
  }
   //Copy constructor (general
  large_integer::large_integer(const large_number& source)
  {
    int cnt = 0;

    while(cnt<LARGE_NUMBER_SIZE)
    {
      data[cnt] = source.getArrayNumber(cnt);
      cnt++;
    }
  }

//Operators----------------------------------------------------------

  const large_integer large_integer::operator+(const large_integer& plus) const
  {
    return add(plus);
  }
  const large_integer large_integer::operator-(const large_integer& minus) const
  {
    return subtract(minus);
  }
  const large_integer large_integer::operator*(const large_integer& multi) const
  {
    return multiply(multi);
  }
  const large_integer large_integer::operator%(const large_integer& modu) const
  {
    return mod(modu);
  }
  const large_integer large_integer::operator/(const large_integer& div) const
  {
    return divide(div);
  }
  
#endif

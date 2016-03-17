/**
 * @file	large_number.h
 * @author	Jonathan Bedard
 * @date   	3/16/2016
 * @brief	Deprecated large number header
 * @bug	Deprecated
 *
 * Deprecated header file which
 * defines the large number used
 * to define public keys in the
 * old version of the gateway.
 **/

///@cond INTERNAL

#ifndef LARGE_NUMBER_H
#define LARGE_NUMBER_H
    
#include <stdint.h>
#include <cstdlib>
#include <time.h>

namespace crypto {
    
const unsigned int LARGE_NUMBER_SIZE=32;
const unsigned int PRIME_TEST_ITERATION=10;

class large_number
{
protected:
  uint32_t data[LARGE_NUMBER_SIZE];
  
  //Opperators
  const large_number add(const large_number& add) const;
  const large_number subtract(const large_number& add) const;
  const large_number leftShift(int x) const;
  const large_number rightShift(int x) const;
  const large_number multiply(const large_number& multi) const;
  const large_number mod(const large_number& mod) const;
  const large_number divide(const large_number& div) const;

  public:
    
  //Constructors
  large_number();
  large_number(uint32_t* array, int length);
  large_number(const large_number& source);
  virtual ~large_number();
  
  bool push_array(uint32_t* array, int length);
  bool push_array_comp_mode(uint32_t* array, int length);
  
  //Public Arithmatic
  const large_number mod_inverse(const large_number& mod) const;
  const large_number gcd(const large_number& mod) const;
  const large_number modExpo(const large_number& pow, const large_number& mod) const;
  bool isPrime() const;
  
  //Accessors
  bool getBit(int bitLoc) const;
  uint32_t getArrayNumber(int index) const;
  const int compare(const large_number& comp) const;
  
  //Output
  void printHex() const;
  void printBinary() const;
  friend std::ostream& operator<<(std::ostream& os, const large_number& obj)
  {
    int cnt = LARGE_NUMBER_SIZE-1;
        
    while(cnt>=0)
    {
        os<<std::dec<<obj.data[cnt];
        cnt--;
        if(cnt>=0)
            os<<":";
    }
    return os;
  }
  
  //Operator
  const large_number& operator=(const large_number& equ);
  const bool operator<(const large_number& comp) const;
  const bool operator>(const large_number& comp) const;
  const bool operator<=(const large_number& comp) const;
  const bool operator>=(const large_number& comp) const;
  const bool operator==(const large_number& comp) const;
  const bool operator!=(const large_number& comp) const;
};

class large_integer:
public large_number
{
public:  
  //Constructors
  large_integer();
  large_integer(uint32_t* array, int length);
  large_integer(const large_number& source);
  
  //Operators
  const large_integer operator+(const large_integer& plus) const;
  const large_integer operator-(const large_integer& minus) const;
  const large_integer operator*(const large_integer& multi) const;
  const large_integer operator%(const large_integer& modu) const;
  const large_integer operator/(const large_integer& div) const;
};

}

#endif

///@endcond
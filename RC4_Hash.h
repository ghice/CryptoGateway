//Primary author: Jonathan Bedard
//Confirmed working: 10/6/2015

#ifndef RC4_HASH_H
#define RC4_HASH_H

#include <string>
#include <iostream>
#include <stdlib.h>

#include "RC4.h"

namespace crypto {

const unsigned int BYTE_SIZE_HASH=32;
extern bool global_logging;

//This is the 
class hash_256
{
private:
  char hash_array[BYTE_SIZE_HASH];

public:
  hash_256();
  hash_256(const char* input);
  hash_256(const hash_256& input);
  
  void push_hash(const char* input);
  char* get_hash();
  
  bool compare(const hash_256& comp) const;

  const hash_256& operator=(const hash_256& equ);
  const bool operator==(const hash_256& comp) const;
  const bool operator!=(const hash_256& comp) const;
  friend std::ostream& operator<<(std::ostream& os, const hash_256& obj)
  {
    int cnt = 0;
        
    while(cnt<BYTE_SIZE_HASH)
    {
        os<<((unsigned int)(unsigned char) obj.hash_array[cnt]);
        cnt++;
        if(cnt<BYTE_SIZE_HASH)
            os<<':';
    }
    return os;
  }
};

static hash_256 build_hash(char* data, int length)
{
  char char_array[BYTE_SIZE_HASH];
  int cnt = 0;
 
  //Initialize return array
  while(cnt<BYTE_SIZE_HASH)
  {
    char_array[cnt] = 0;
    cnt++;
  }
  
  int value = 0;
  int len;
  
  while(value<length)
  {
    if((length-value) > BYTE_SIZE_HASH)
      len = BYTE_SIZE_HASH;
    else
      len = length-value;
    
    RCFour rc((uint8_t*)&data[value], len);
    value = value+len;
    
    cnt = 0;
    while(cnt<BYTE_SIZE_HASH)
    {
      char_array[cnt] = char_array[cnt]^rc.getNext();
      cnt++;
    }
  }
  hash_256 ret(char_array);
  
  return ret;
}

}

#endif
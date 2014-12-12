//Primary author: Jonathan Bedard
//Confirmed working: 10/9/2014

#ifndef RC4_HASH_CPP
#define RC4_HASH_CPP

#include "RC4_Hash.h"

using namespace std;

//Default hash constructor
hash_256::hash_256()
{
  int cnt = 0;
  while(cnt<BYTE_SIZE_HASH)
  {
    hash_array[cnt] = 0;
    cnt++;
  }
}
//Construct with hash character input
hash_256::hash_256(const char* input)
{
  push_hash(input);
}
//Copy constructor
hash_256::hash_256(const hash_256& input)
{
  push_hash(input.hash_array);
}
//Pushes a hash into the data type
void hash_256::push_hash(const char* input)
{
  int cnt = 0;
  while(cnt<BYTE_SIZE_HASH)
  {
    hash_array[cnt] = input[cnt];
    cnt++;
  }
}
//Returns the character array of the hash
char* hash_256::get_hash()
{
  return hash_array;
}
//Compares two hashes for equality
bool hash_256::compare(const hash_256& comp) const
{
  int cnt = 0;

  while(cnt< BYTE_SIZE_HASH)
  {
    if(comp.hash_array[cnt]!=hash_array[cnt])
	{
      return false;
	}
    cnt++;
  }
  cout<<"True"<<endl;
  return true;
}
//Assignment operator
const hash_256& hash_256::operator=(const hash_256& equ)
{
  push_hash(equ.hash_array);
  return equ;
}
//Comparison operators
const bool hash_256::operator==(const hash_256& comp) const
{
  return compare(comp);
}
const bool hash_256::operator!=(const hash_256& comp) const
{
  return !compare(comp);
}
//Stream operator
std::ostream& operator<<(std::ostream& os, const hash_256& obj)
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

#endif
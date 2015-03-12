//Primary author: Jonathan Bedard
//Certified working 10/28/2014

#ifndef INTERIOR_MESSAGE_CPP
#define INTERIOR_MESSAGE_CPP

#include "interior_message.h"

using namespace std;

//Default constructor
interior_message::interior_message()
{
  int cnt = 0;
  length = 0;

  while(cnt<MESSAGE_MAX)
  {
    message_data[cnt] = 0;
    cnt++;
  }
}
//Character array constructor
interior_message::interior_message(char* data, int len)
{
  push_data(data, len);
}
//8 bit integer array constructor
interior_message::interior_message(uint8_t* data, int len)
{
  push_data(data, len);
}
//Copy constructor
interior_message::interior_message(const interior_message& source)
{
  push_data((uint8_t*)source.message_data,source.length);
}
//Equality operator
const interior_message& interior_message::operator=(const interior_message& equ)
{
  push_data((uint8_t*)equ.message_data,equ.length);
  return  equ;
}

//Prints out the message
ostream& operator<<(ostream& os, const interior_message& obj)
{
  int cnt = 0;
  while(cnt<obj.length)
  {
    os<<(uint32_t) obj.message_data[cnt];
    cnt++;
    if(cnt<obj.length)
      os<<':';
  }
  return os;
}

//Pushes data onto the message, clearing an old message
void interior_message::push_data(char* data, int len)
{
  push_data((uint8_t*)data,len);
}
//Pushes data onto the message, clearing an old message
void interior_message::push_data(uint8_t* data, int len)
{
  int cnt = 0;
  length = len;
  while(cnt<length&&cnt<MESSAGE_MAX)
  {
    message_data[cnt] = data[cnt];
    cnt++;
  }
  while(cnt<MESSAGE_MAX)
  {
    message_data[cnt] = 0;
    cnt++;
  }
}
//Sets the length
void interior_message::push_length(int len)
{
  length = len;
}

//Returns the actual message length
int interior_message::get_length() const
{
  return length;
}
//Returns the full length of the message
int interior_message::get_full_length() const
{
  return MESSAGE_MAX;
}

//Returns the data, as a character array
char* interior_message::get_char_data()
{
  return (char*) message_data;
}
uint8_t* interior_message::get_int_data()
{
  return message_data;
}
#endif
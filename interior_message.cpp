/**
 * @file	interior_message.cpp
 * @author	Jonathan Bedard
 * @date   	3/16/2016
 * @brief	Deprecated interior message
 * @bug	Deprecated
 *
 * Deprecated implementation file which
 * defines the message to be
 * encrypted by the gateway
 **/

///@cond INTERNAL

#ifndef INTERIOR_MESSAGE_CPP
#define INTERIOR_MESSAGE_CPP

#include "cryptoLogging.h"
#include "interior_message.h"
#include "file_mechanics.h"
#include <string>

using namespace std;
using namespace crypto;

/*------------------------------------------------------------
    Interior Message
------------------------------------------------------------*/

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

//Pushes data onto the message, clearing an old message
void interior_message::push_data(char* data, int len)
{
  push_data((uint8_t*)data,len);
}
//Pushes data onto the message, clearing an old message
void interior_message::push_data(uint8_t* data, int len)
{
  int cnt = 0;
    push_length(len);
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
    if(len>MESSAGE_MAX)
    {
        cryptoerr<<"Message length error! Bounding message length"<<endl;
        length = MESSAGE_MAX;
        return;
    }
    length = len;
}

//Returns the last data position
int interior_message::get_data_end()
{
    return length;
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
//Adds a string to the end of the message (include length)
bool interior_message::push_string(std::string s)
{
    //Bound checks
    if(s.length()>255)
    {
        cryptoerr<<"String length greater than allowed!  Returning true to exit logic"<<endl;
        return true;
    }
	if(get_data_end()+s.length()+1>get_full_length())
        return false;
    int old_len = get_data_end();
    push_length(get_data_end()+s.length()+1);
    int trace = 0;
    while(trace<s.length())
    {
        message_data[old_len+trace]=s.c_str()[trace];
        trace++;
    }
    message_data[old_len+trace]=(uint8_t)s.length();
    return true;
}
//Removes a string from the message
std::string interior_message::pop_string()
{
    int data_end = get_data_end()-1;
    int targ_len = message_data[data_end];

    if(targ_len==0||targ_len>data_end)
        return "";

    string ret = "";
    int cnt = 0;
    while(cnt<targ_len)
    {
        ret = ((char)message_data[data_end-(cnt+1)])+ret;
        cnt++;
    }
    
    push_length(data_end-(targ_len));
    return ret;
}

/*------------------------------------------------------------
 Checksum Message
 ------------------------------------------------------------*/

//Just call the interior message versions, checksum is only an action modifier
checksum_message::checksum_message()
{
    //Default constructor implicitly called
}
checksum_message::checksum_message(char* data, int len):
	interior_message(data,len) {push_length(len);}
checksum_message::checksum_message(uint8_t* data, int len):
	interior_message(data,len) {push_length(len);}
checksum_message::checksum_message(const interior_message& source):
	interior_message(source) {}

//Returns the last data position
int checksum_message::get_data_end()
{
    if(CHECKSUM_SIZE>length)
        return 0;
    return length-CHECKSUM_SIZE;
}
//Pushes the length onto the message (checksum bounds)
void checksum_message::push_length(int len)
{
    if(len>MESSAGE_MAX-CHECKSUM_SIZE)
    {
        cryptoerr<<"Message length error (checksum)! Bounding message length"<<endl;
        length = MESSAGE_MAX;
        return;
    }
    length = len+CHECKSUM_SIZE;
}
//Returns the longest possible length (checksum bounds)
int checksum_message::get_full_length() const
{
    return MESSAGE_MAX-CHECKSUM_SIZE;
}

//Generates a checksum
uint32_t checksum_message::generate_checksum()
{
    if(length-4<CHECKSUM_SIZE)
        return 0;
    int cnt2=0;
    uint8_t trace[CHECKSUM_SIZE];
    for(int cnt = 0;cnt<CHECKSUM_SIZE;cnt++)
    {
        trace[cnt]=0;
    }
    for(int cnt = 4;cnt<length-CHECKSUM_SIZE;cnt++)
    {
        trace[cnt2] = trace[cnt2]^message_data[cnt];
        cnt2 = (cnt2+1)%CHECKSUM_SIZE;
    }
    
    return to_comp_mode_sgtw(*((uint32_t*)trace));
}
//Returns a checksum
uint32_t checksum_message::get_checksum()
{
    if(length<CHECKSUM_SIZE)
        return 0;
    uint32_t ret;
    int trace=0;
    for(int cnt = CHECKSUM_SIZE;cnt>0;cnt--)
    {
        ((char*)&ret)[trace] = message_data[length-cnt];
        trace++;
    }
    
    return from_comp_mode_sgtw(ret);
}
//Binds a checksum
void checksum_message::bind_checksum()
{
    uint32_t chx = generate_checksum();
    
    int trace=0;
    for(int cnt = CHECKSUM_SIZE;cnt>0;cnt--)
    {
        message_data[length-cnt] = ((char*)&chx)[trace];
        trace++;
    }
}
//Compares the generated and grabbed checksum
bool checksum_message::check_checksum()
{
    if(get_checksum()!=generate_checksum())
	{
		cryptoout<<get_checksum()<<" : "<<generate_checksum()<<std::endl;
        return false;
	}
    return true;
}

#endif

///@endcond
//Primary author: Jonathan Bedard
//Certified working 9/2/14

#ifndef FILE_MECHANICS_H
#define FILE_MECHANICS_H

#include <string.h>
#include <stdint.h>
#include <iostream>
#include <fstream>
#include <ctime>
#include <math.h> 

using namespace std;

//Test if a file exists
static bool file_exists(const string& file_name)
{
  ifstream tst(file_name.c_str());
  if(tst.good())
  {
    tst.close();
    return true;
  }
  else
    tst.close();
  return false;
}
//Returns the 64 bit time stamp
static uint64_t get_timestamp()
{
  time_t ttstamp = time(0);
  return (uint64_t) ttstamp;
}
//Tests if a character is numberic
static bool check_numeric(const char char_to_check)
{
  if('0'==char_to_check)
    return true;
  if('1'==char_to_check)
    return true;
  if('2'==char_to_check)
    return true;
  if('3'==char_to_check)
    return true;
  if('4'==char_to_check)
    return true;
  if('5'==char_to_check)
    return true;
  if('6'==char_to_check)
    return true;
  if('7'==char_to_check)
    return true;
  if('8'==char_to_check)
    return true;
  if('9'==char_to_check)
    return true;
  return false;
}
//Convert a char to an integer
static int conver_char_int(const char char_to_check)
{
  if('0'==char_to_check)
    return 0;
  if('1'==char_to_check)
    return 1;
  if('2'==char_to_check)
    return 2;
  if('3'==char_to_check)
    return 3;
  if('4'==char_to_check)
    return 4;
  if('5'==char_to_check)
    return 5;
  if('6'==char_to_check)
    return 6;
  if('7'==char_to_check)
    return 7;
  if('8'==char_to_check)
    return 8;
  if('9'==char_to_check)
    return 9;
  return 0;
}
//Converts a string to an unsigned 64 bit integer
static uint64_t convert_64(const string& str)
{
  uint64_t ret = 0;
  int hld;
  int cnt = 0;
  
  while(cnt<str.length())
  {
    hld = conver_char_int(str.at(str.length()-1-cnt));
    ret = ret+hld*(pow(10,cnt));
    cnt++;
  }
  
  return ret;
}

#endif

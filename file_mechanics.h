/**
 * @file   file_mechanics.h
 * @author Jonathan Bedard
 * @date   3/2/2016
 * @brief  Deprecated file functions
 * @bug No known bugs.
 *
 * The functions defined in this file
 * were moved into the osMechanics library.
 * This file is slowly being phased on.
 *
 */

///@cond INTERNAL

#ifndef FILE_MECHANICS_H
#define FILE_MECHANICS_H

#include <string.h>
#include <stdint.h>
#include <iostream>
#include <fstream>
#include <ctime>
#include <cmath>

namespace crypto {
extern bool global_logging;

//Changes an int to compatibility mode
static uint16_t to_comp_mode_sgtw(uint16_t i)
{
    uint16_t temp = 1;
    //Switch little to big endian
    if(((char*) &temp)[0] == 0)
    {
        ((char*) &temp)[0] = ((char*) &i)[1];
        ((char*) &temp)[1] = ((char*) &i)[0];
        return temp;
    }
    return i;
}
//Changes an int from compatibility mode to system mode
static uint16_t from_comp_mode_sgtw(uint16_t i)
{
    uint16_t temp = 1;
    //Switch little to big endian
    if(((char*) &temp)[0] == 0)
    {
        ((char*) &temp)[0] = ((char*) &i)[1];
        ((char*) &temp)[1] = ((char*) &i)[0];
        return temp;
    }
    return i;
}
//Changes an int to compatibility mode
static uint32_t to_comp_mode_sgtw(uint32_t i)
{
    uint32_t temp = 1;
    //Switch little to big endian
    if(((char*) &temp)[0] == 0)
    {
        ((char*) &temp)[0] = ((char*) &i)[3];
        ((char*) &temp)[1] = ((char*) &i)[2];
        ((char*) &temp)[2] = ((char*) &i)[1];
        ((char*) &temp)[3] = ((char*) &i)[0];
        return temp;
    }
    return i;
}
//Changes an int from compatibility mode to system mode
static uint32_t from_comp_mode_sgtw(uint32_t i)
{
    uint32_t temp = 1;
    //Switch little to big endian
    if(((char*) &temp)[0] == 0)
    {
        ((char*) &temp)[0] = ((char*) &i)[3];
        ((char*) &temp)[1] = ((char*) &i)[2];
        ((char*) &temp)[2] = ((char*) &i)[1];
        ((char*) &temp)[3] = ((char*) &i)[0];
        return temp;
    }
    return i;
}
//Changes an int to compatibility mode
static uint64_t to_comp_mode_sgtw(uint64_t i)
{
    uint64_t temp = 1;
    //Switch little to big endian
    if(((char*) &temp)[0] == 0)
    {
        ((char*) &temp)[0] = ((char*) &i)[7];
        ((char*) &temp)[1] = ((char*) &i)[6];
        ((char*) &temp)[2] = ((char*) &i)[5];
        ((char*) &temp)[3] = ((char*) &i)[4];
        ((char*) &temp)[4] = ((char*) &i)[3];
        ((char*) &temp)[5] = ((char*) &i)[2];
        ((char*) &temp)[6] = ((char*) &i)[1];
        ((char*) &temp)[7] = ((char*) &i)[0];
        return temp;
    }
    return i;
}
//Changes an int from compatibility mode to system mode
static uint64_t from_comp_mode_sgtw(uint64_t i)
{
    uint64_t temp = 1;
    //Switch little to big endian
    if(((char*) &temp)[0] == 0)
    {
        ((char*) &temp)[0] = ((char*) &i)[7];
        ((char*) &temp)[1] = ((char*) &i)[6];
        ((char*) &temp)[2] = ((char*) &i)[5];
        ((char*) &temp)[3] = ((char*) &i)[4];
        ((char*) &temp)[4] = ((char*) &i)[3];
        ((char*) &temp)[5] = ((char*) &i)[2];
        ((char*) &temp)[6] = ((char*) &i)[1];
        ((char*) &temp)[7] = ((char*) &i)[0];
        return temp;
    }
    return i;
}

//Test if a file exists
static bool file_exists(const std::string& file_name)
{
  std::ifstream tst(file_name.c_str());
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
//Returns a timestamp converted to a string
static std::string convertTimestamp(uint64_t stamp)
{
	if(stamp==0)
		return "No date";
	time_t rawtime = (time_t) stamp;
	struct tm timeinfo;
	char buffer [200];

    #ifdef _WIN32
	localtime_s (&timeinfo,&rawtime);
    #else
    localtime_r (&rawtime,&timeinfo);
    #endif

	strftime (buffer,200,"%m/%d/%Y at %I:%M %p",&timeinfo);
	return std::string(buffer);
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
static uint64_t convert_64(const std::string& str)
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

}

#endif

///@endcond
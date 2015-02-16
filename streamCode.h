//Primary author: Jonathan Bedard
//Confirmed working: 9/29/2014

//The stream sender/reciever header file

#ifndef STREAMCODE_H
#define STREAMCODE_H

#include <stdint.h>
#include "RC4.h"

#define PACKETSIZE 508
#define DECRYSIZE 100
#define BACKCHECK 10
#define LAGCATCH ((int) DECRYSIZE/4)

//Encrypts a byte stream
class streamEncrypter
{
private:
  RCFour* cipher;
  int last_loc;
  uint16_t ID_check[BACKCHECK];

public:
  streamEncrypter(RCFour* c);
  virtual ~streamEncrypter();

  uint8_t* sendData(uint8_t* array, int len, uint16_t* flag);
};

//Decrypts a byte stream
class streamDecrypter
{
private:
  RCFour* cipher;
  codePacket** packetArray;
  int last_value;
  int mid_value;
  
public:
  streamDecrypter(RCFour* c);
  virtual ~streamDecrypter();

  
  uint8_t* recieveData(uint8_t* array, int len, uint16_t flag);
  
  
};

#endif
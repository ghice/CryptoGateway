//Primary author: Jonathan Bedard
//Confirmed working: 9/26/2014

//The implementation of the basic RC4 cipher and its packet

#ifndef RC4_CPP
#define RC4_CPP

#include "RC4.h"

#include <string>
#include <iostream>
#include <stdlib.h>

using namespace std;

//Default RC4-----------------------------------------------------------------

  //Constructor
  RCFour::RCFour(uint8_t* arr, int len)
  {
    //Check the array length
    if(RC4MAX<len)
    {
      cerr<<"Invalid initialization array in the default RCFour"<<endl;
      exit(EXIT_FAILURE);
    }

    //Initialize the S array
    SArray  = new uint8_t [RC4MAX];

    i = 0;
    while(i<RC4MAX)
    {
      SArray[i] = i;
      i++;
    }

    //Set the initial permutaion

    i = 0;
    j = 0;

    while(i<RC4MAX)
    {
      j=(j+SArray[i]+arr[i%len])%RC4MAX;
      u = SArray[i];
      SArray[i] = SArray[j];
      SArray[j] = u;
      i++;
    }

    i = 0;
    j = 0;
    u = 0;
  }
  //Destructor
  RCFour::~RCFour()
  {
    delete(SArray);
  }
  //Return the next element the stream generates
  uint8_t RCFour::getNext()
  {
    int temp;

    u++;
    i = (i+1)%RC4MAX;
    j = (j+ SArray[i])%RC4MAX;

    temp = SArray[i];
    SArray[i] = SArray[j];
    SArray[j] = temp;
    return ((uint8_t) (SArray[(SArray[i]+SArray[j])%RC4MAX]));
  }

//Code Packet-----------------------------------------------------------------

  //Constructor
  codePacket::codePacket(RCFour* source, int s)
  {
    if(s>0)
      size = s;
    else
    {
      cerr<<"Negative size bound in the codePacket constructor"<<endl;
      exit(EXIT_FAILURE);
    }
    if(s<20)
    {
      cerr<<"Warning: This buffer length may give away too much information about the secret key: codePacket"<<endl;
    }

    //Initialize the packet Array
    int cnt = 0;
    packetArray = new uint8_t[size];
    packetArray[0] = source->getNext();
    packetArray[1] = source->getNext();
    
    identifier = (((uint16_t) packetArray[0])<<8) ^ packetArray[1];

    while(cnt<size)
    {
      packetArray[cnt] = source->getNext();
      cnt++;
    }

    
  }
  //Destructor
  codePacket::~codePacket()
  {
    delete(packetArray);
  }
  //Returns the identifier
  uint16_t codePacket::getIdentifier()
  {
	return identifier;
  }
  //Returns the packet data
  uint8_t* codePacket::getPacket()
  {
    return packetArray;
  }
  //Encrypts a given packet, automatic suppression
  uint8_t* codePacket::encrypt(uint8_t* pt, int len)
  {
    return encrypt(pt, len, true);
  }
  //Encrypts, dynamic suppression
  uint8_t* codePacket::encrypt(uint8_t* pt, int len, bool surpress)
  {
    if(!surpress && len>size)
    {
      cerr<<"The length of your input to codePacket.encrypt() is unsecure!  Abort!"<<endl;
      exit(EXIT_FAILURE);
    }
    int cnt = 0;
    while(cnt<len)
    {
      pt[cnt] = pt[cnt] ^ packetArray[cnt%size];
      cnt++;
    }

    return pt;
  }

#endif
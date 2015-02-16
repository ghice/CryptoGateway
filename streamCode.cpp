//Primary author: Jonathan Bedard
//Confirmed working: 9/26/2014

//The stream sender/reciever header file

#ifndef STREAMCODE_CPP
#define STREAMCODE_CPP

#include <string>
#include <iostream>
#include <stdlib.h>
#include "streamCode.h"
#include "RC4.h"

using namespace std;

//Stream Encrypter---------------------------------------------------------------------------

  //Constructor
  streamEncrypter::streamEncrypter(RCFour* c)
  {
    cipher = c;
    last_loc = 0;
    
    //Set ID array to 0
    int cnt = 0;
    while(cnt<BACKCHECK)
    {
      ID_check[cnt] = 0;
      cnt++;
    }
  }
  //Destructor
  streamEncrypter::~streamEncrypter()
  {
    delete(cipher);
  }
  //Encrypts an array
  uint8_t* streamEncrypter::sendData(uint8_t* array, int len, uint16_t* flag)
  {
    if(len>PACKETSIZE)
    {
      cerr<<"Invalid packet size for stream encrypter!"<<endl;
      exit(EXIT_FAILURE);
    }
    
    //Check to ensure we have a good identifier
    codePacket* en;
    bool packet_found = false;
    do
    {
      en = new codePacket (cipher, PACKETSIZE);
      ID_check[last_loc] = (uint16_t) en->getIdentifier();
      
      int cnt = 0;
      packet_found = true;
      while(cnt<BACKCHECK && packet_found)
      {
	if(ID_check[last_loc]==0 || 
	  (last_loc!=cnt && ID_check[cnt] == ID_check[last_loc]))
	{
	  packet_found = false;
	}
	cnt++;
      }
      
      if(!packet_found)
	delete(en);
    }
    while(!packet_found);
    
    //Encrypt and return
    last_loc=(last_loc+1) % BACKCHECK;
    (*flag) = (uint16_t) en->getIdentifier();
    en->encrypt(array, len);
    delete(en);
    return array;
  }

//Stream Decypter----------------------------------------------------------------------------

  //Constructor
  streamDecrypter::streamDecrypter(RCFour* c)
  {
    cipher = c;
    last_value = 0;
    mid_value = LAGCATCH-1;
    packetArray = new codePacket*[DECRYSIZE];
    
    int cnt = 0;
    
	//Initialize packets to NULL
	while(cnt<DECRYSIZE)
	{
		packetArray[cnt] = NULL;
		cnt++;
	}
	cnt=0;

    //Create the packetArray checks
    while(cnt<DECRYSIZE)
    {
      bool good_packet;
      do
      {
			packetArray[cnt] = new codePacket(cipher, PACKETSIZE);
			good_packet = true;
	
			if(packetArray[cnt]->getIdentifier()==0)
				good_packet = false;
	
			int cnt2 = 1;
			while(cnt2<BACKCHECK && good_packet)
			{
				if(packetArray[(DECRYSIZE+cnt-cnt2)%DECRYSIZE]!=NULL && 
					packetArray[(DECRYSIZE+cnt-cnt2)%DECRYSIZE]->getIdentifier()==packetArray[cnt]->getIdentifier())
					good_packet = false;
	    
				cnt2++;
			}
			if(!good_packet)
				delete(packetArray[cnt]);
      }
      while(!good_packet);
      cnt++;
    }
  }
  //Destructor
  streamDecrypter::~streamDecrypter()
  {
    int cnt = 0;
    while(cnt<DECRYSIZE)
    {
      if(packetArray[cnt]!=NULL)
	delete(packetArray[cnt]);
      cnt++;
    }
    delete(packetArray);
    delete(cipher);
  }
  //Encrypts an array
  uint8_t* streamDecrypter::recieveData(uint8_t* array, int len, uint16_t flag)
  {
    if(len>PACKETSIZE)
    {
      cerr<<"Invalid packet size for stream decrypter!"<<endl;
      exit(EXIT_FAILURE);
    }
    
    //Find the flag
    int cnt = 2;
    bool found = false;
    while(cnt<DECRYSIZE && !found)
    {
      if(packetArray[(cnt+last_value+DECRYSIZE-BACKCHECK)%DECRYSIZE]->getIdentifier()==flag)
	found = true;
      if(!found)
	cnt++;
    }
    
    //Check if we have found the packet
    if(!found)
    {
      cerr<<"Stream broken.  Return NULL"<<endl;
      return NULL;
    }

    //Preform the decryption
    packetArray[(cnt+last_value+DECRYSIZE-BACKCHECK)%DECRYSIZE]->encrypt(array,len);
    
    //Change save array
    last_value = (cnt+last_value+DECRYSIZE-BACKCHECK)%DECRYSIZE;
    //cout<<"Last value:"<<last_value<<"\tMid value:"<<mid_value<<endl;
    if((last_value<mid_value && last_value>((mid_value-LAGCATCH+DECRYSIZE) % DECRYSIZE)) ||
      (mid_value<((mid_value-LAGCATCH+DECRYSIZE) % DECRYSIZE) && (last_value<mid_value || last_value>((mid_value-LAGCATCH+DECRYSIZE) % DECRYSIZE)))||
    last_value==mid_value)
      return array;

    //Add the needed packets
    int difference = (last_value - mid_value+DECRYSIZE)%DECRYSIZE;
    cnt = 0;
    
    while(cnt<difference)
    {
      bool good_packet;
      //Confirm the packet is good
      do
      {
	good_packet = true;
	if(packetArray[(mid_value+DECRYSIZE-LAGCATCH+cnt+1)%DECRYSIZE]!=NULL)
	  delete(packetArray[(mid_value+DECRYSIZE-LAGCATCH+cnt+1)%DECRYSIZE]);
	packetArray[(mid_value+DECRYSIZE-LAGCATCH+cnt+1)%DECRYSIZE] = new codePacket(cipher, PACKETSIZE);
	
	if(packetArray[(mid_value+DECRYSIZE-LAGCATCH+cnt+1)%DECRYSIZE]->getIdentifier()==0)
	  good_packet = false;
	int local_cnt = 1;
	while(good_packet&&local_cnt<BACKCHECK)
	{
	  if(packetArray[(mid_value+DECRYSIZE-LAGCATCH+cnt+1)%DECRYSIZE]->getIdentifier()==
	    packetArray[(mid_value+DECRYSIZE-LAGCATCH+cnt+1-local_cnt)%DECRYSIZE]->getIdentifier())
	    good_packet = false;
	  local_cnt++;
	}
      }
      while(!good_packet);
      cnt++;
    }
    mid_value = last_value;
    
    return array;
  }
#endif
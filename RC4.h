//Primary author: Jonathan Bedard
//Confirmed working: 7/29/2014

//Defines an RC4 stream cipher

#ifndef RC4_H
#define RC4_H
    
#include <stdint.h>

namespace crypto {
    
#define RC4MAX 2506
class RCFour
{
private:
	uint8_t* SArray;
	int i;
	int j;
	int u;

public:
	//Constructor
	RCFour(uint8_t* arr, int len);
	virtual ~RCFour();

	virtual uint8_t getNext();
};

class codePacket
{
private:
  uint8_t* packetArray;
  uint16_t identifier;
  int size;
  
public:
  codePacket(RCFour* source, int s);
  virtual ~codePacket();

  uint16_t getIdentifier();
  uint8_t* getPacket();
  uint8_t* encrypt(uint8_t* pt, int len);
  uint8_t* encrypt(uint8_t* pt, int len, bool surpress);
};

}

#endif

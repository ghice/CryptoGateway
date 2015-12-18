//Primary author: Jonathan Bedard
//Certified working 12/18/2015

#ifndef HEX_CONVERSION_H
#define HEX_CONVERSION_H
   
#include <memory>
#include <stdint.h>
#include <cstdlib>
#include <iostream>
#include <string>

namespace crypto {
    
    bool isHexCharacter(char c);
    
    std::string toHex(unsigned char i);
    std::string toHex(uint32_t i);
    
    uint32_t fromHex32(const std::string& str);
}

#endif
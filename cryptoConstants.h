//Primary author: Jonathan Bedard
//Confirmed working: 12/17/2015

#ifndef CRYPTOCONSTANTS_H
#define CRYPTOCONSTANTS_H

#include "C_Algorithms/cryptoCConstants.h"

#include <string>

//Scoped C++ variables
namespace crypto
{
	namespace numberType
	{
		extern const int Default;
		extern const int Base10;
	}
	namespace numberName
	{
		extern const std::string Default;
		extern const std::string Base10;
	}
    namespace algo
    {
        extern const uint16_t primeTestCycle;
        
        extern const uint16_t hashNULL;
        extern const uint16_t hashXOR;
    }
    namespace size
    {
        extern const uint16_t hash64;
        extern const uint16_t hash128;
        extern const uint16_t hash256;
        extern const uint16_t hash512;
        extern const uint16_t defaultHash;
    }
}

#endif
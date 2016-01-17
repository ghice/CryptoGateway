//Primary author: Jonathan Bedard
//Confirmed working: 1/15/2016

#ifndef CRYPTOCONSTANTS_H
#define CRYPTOCONSTANTS_H

#include "C_Algorithms/cryptoCConstants.h"

#include <stdint.h>
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
        extern const uint16_t hashRC4;
		
		extern const uint16_t streamNULL;
		extern const uint16_t streamRC4;
    }
    namespace size
    {
        extern const uint16_t hash64;
        extern const uint16_t hash128;
        extern const uint16_t hash256;
        extern const uint16_t hash512;
        extern const uint16_t defaultHash;

		extern const uint16_t STREAM_SEED_MAX;
		extern const uint16_t RC4_MAX;
		
		namespace stream
		{
			extern const uint16_t PACKETSIZE;
			extern const uint16_t DECRYSIZE;
			extern const uint16_t BACKCHECK;
			extern const uint16_t LAGCATCH;
		}
    }
}

#endif
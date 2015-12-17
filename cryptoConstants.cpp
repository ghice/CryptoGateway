//Primary author: Jonathan Bedard
//Confirmed working: 12/17/2015

#ifndef CRYPTOCONSTANTS_CPP
#define CRYPTOCONSTANTS_CPP

#include "cryptoConstants.h"
#include <string>

namespace crypto
{
	namespace numberType
	{
		const int Default=crypto_numbertype_default;
		const int Base10=crypto_numbertype_base10;
	}
	namespace numberName
	{
		const std::string Default=std::string(crypto_numbername_default);
		const std::string Base10=std::string(crypto_numbername_base10);
	}
    namespace algo
    {
        const uint16_t primeTestCycle=20;
        
        const uint16_t hashNULL=0;
        const uint16_t hashXOR=1;
    }
    namespace size
    {
        const uint16_t hash64=8;
        const uint16_t hash128=16;
        const uint16_t hash256=32;
        const uint16_t hash512=64;
        const uint16_t defaultHash=hash256;
    }
}

#endif
//Primary author: Jonathan Bedard
//Confirmed working: 8/29/2015

#ifndef CRYPTO_LOGGING_H
#define CRYPTO_LOGGING_H

#include <iostream>

namespace crypto
{

    //OS Logger Streams
	extern bool global_logging;
    extern std::ostream* cryptoout_ptr;
    extern std::ostream* cryptoerr_ptr;
    #define cryptoout (*cryptoout_ptr)
    #define cryptoerr (*cryptoerr_ptr)

}

#endif
//Primary author: Jonathan Bedard
//Confirmed working: 8/21/2015

#ifndef CRYPTO_LOGGING_H
#define CRYPTO_LOGGING_H

#include <iostream>

namespace crypto
{

    //OS Logger Streams
    extern std::ostream* cryptoout_ptr;
    extern std::ostream* cryptoerr_ptr;
    #define cryptoout (*cryptoout_ptr)
    #define cryptoerr (*cryptoerr_ptr)

}

#endif
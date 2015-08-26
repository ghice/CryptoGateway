//Primary author: Jonathan Bedard
//Confirmed working: 8/21/2015

#ifndef CRYPTO_LOGGING_CPP
#define CRYPTO_LOGGING_CPP

#include "cryptoLogging.h"

//OS Logger Streams
std::ostream* crypto::cryptoout_ptr = &(std::cout);
std::ostream* crypto::cryptoerr_ptr = &(std::cerr);

#endif

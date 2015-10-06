//Primary author: Jonathan Bedard
//Confirmed working: 8/29/2015

#ifndef CRYPTO_LOGGING_CPP
#define CRYPTO_LOGGING_CPP

#include "cryptoLogging.h"

//OS Logger Streams
bool crypto::global_logging = false;
std::ostream* crypto::cryptoout_ptr = &(std::cout);
std::ostream* crypto::cryptoerr_ptr = &(std::cerr);

std::ostream& crypto::cryptoout_func() {return *crypto::cryptoout_ptr;}
std::ostream& crypto::cryptoerr_func() {return *crypto::cryptoerr_ptr;}

#endif

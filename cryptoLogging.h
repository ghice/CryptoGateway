//Primary author: Jonathan Bedard
//Confirmed working: 10/12/2015

#ifndef CRYPTO_LOGGING_H
#define CRYPTO_LOGGING_H

#include <iostream>
#include "smartPointer.h"

namespace crypto
{

    //OS Logger Streams
	extern bool global_logging;
	extern os::smart_ptr<std::ostream> cryptoout_ptr;
    extern os::smart_ptr<std::ostream> cryptoerr_ptr;

	std::ostream& cryptoout_func();
	std::ostream& cryptoerr_func();
}
#ifndef cryptoout
#define cryptoout cryptoout_func()
#endif
#ifndef cryptoerr
#define cryptoerr cryptoerr_func()
#endif

#endif
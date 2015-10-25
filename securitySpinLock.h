//Primary author: Jonathan Bedard
//Confirmed working: 10/24/2015

#ifdef _WIN32
#include "Windows/securitySpinLock.h"
#else
#include "Unix/securitySpinLock.h"
#endif
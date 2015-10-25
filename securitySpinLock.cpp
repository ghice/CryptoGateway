//Primary author: Jonathan Bedard
//Confirmed working: 10/24/2015

#ifdef WIN32
#include "Windows/securitySpinLock.cpp"
#else
#include "Unix/securitySpinLock.cpp"
#endif
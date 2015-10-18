//Primary author: Jonathan Bedard
//Confirmed working: 10/17/2015

#ifdef _WIN32
#include "Windows/securitySpinLock.cpp"
#else
#include "Unix/securitySpinLock.cpp"
#endif
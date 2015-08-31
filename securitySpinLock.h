//Primary author: Jonathan Bedard
//Confirmed working: 8/16/2015

/*
WINDOWS ONLY
*/

#ifndef SECURITYSPINLOCK_H
#define SECUROTYSPINLOCK_H

#include <atomic>

namespace crypto
{
extern bool global_logging;

//This is a simple spinlock class
class sgSpinLock
{
private:
    std::atomic_flag lock;
	bool taken;
public:
	sgSpinLock();
	~sgSpinLock();
    void acquire();
    void release();
	bool isTaken();
};
    
}

#endif
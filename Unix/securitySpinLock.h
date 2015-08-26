//Primary author: Jonathan Bedard
//Confirmed working: 8/16/2015

/*
UNIX ONLY
*/

#ifndef SECURITYSPINLOCK_H
#define SECURITYSPINLOCK_H

#include <pthread.h>

namespace crypto
{

//This is a simple spinlock class
class sgSpinLock
{
private:
    pthread_mutex_t spinlock;
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

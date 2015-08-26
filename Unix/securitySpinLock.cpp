//Primary author: Jonathan Bedard
//Confirmed working: 8/16/2015

/*
UNIX ONLY
*/

#ifndef SECURITYSPINLOCK_CPP
#define SECURITYSPINLOCK_CPP

#include "securitySpinLock.h"
#include <pthread.h>

using namespace std;
using namespace crypto;

//Default constructor
sgSpinLock::sgSpinLock()
{
	release();
}
//Default destructor
sgSpinLock::~sgSpinLock(){}
//Acquire the lock
void sgSpinLock::acquire()
{
	pthread_mutex_lock(&spinlock);
	taken = true;
}
//Release the lock
void sgSpinLock::release()
{
	pthread_mutex_unlock(&spinlock);
	taken = false;
}
//Test the lock (non blocking)
bool sgSpinLock::isTaken()
{
	return taken;
}

#endif

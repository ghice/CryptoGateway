//Primary author: Jonathan Bedard
//Confirmed working: 10/23/2015

/*
UNIX ONLY
*/

#ifndef SECURITYSPINLOCK_CPP
#define SECURITYSPINLOCK_CPP

#include "../securitySpinLock.h"
#include <pthread.h>

using namespace std;
using namespace crypto;

//Default constructor
sgSpinLock::sgSpinLock()
{
	pthread_mutex_init(&spinlock, NULL);
}
//Default destructor
sgSpinLock::~sgSpinLock()
{
	pthread_mutex_destroy(&spinlock);
}
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

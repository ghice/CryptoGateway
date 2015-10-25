//Primary author: Jonathan Bedard
//Confirmed working: 10/24/2015

/*
WINDOWS ONLY
*/

#ifndef SECURITYSPINLOCK_CPP
#define SECURITYSPINLOCK_CPP

#include "../securitySpinLock.h"
#include <process.h>
#include <Windows.h>

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
	while (lock.test_and_set(memory_order_acquire))
	{Sleep(1);}
	taken = true;
}
//Release the lock
void sgSpinLock::release()
{
	lock.clear(memory_order_release);
	taken = false;
}
//Test the lock (non blocking)
bool sgSpinLock::isTaken()
{
	return taken;
}
#endif

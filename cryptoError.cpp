//Primary author: Jonathan Bedard
//Certified working 1/17/2016

#ifndef CRYPTO_ERROR_CPP
#define CRYPTO_ERROR_CPP
 
#include "cryptoError.h"

namespace crypto {

/*------------------------------------------------------------
     Error Listener
 ------------------------------------------------------------*/

	//Deletes an error listener
	errorListener::~errorListener()
	{
		senders.resetTraverse();
		for(auto trc=senders.getFirst();trc;trc=trc->getNext())
		{
			trc->getData()->listenerLock.acquire();
			mtx.acquire();
			trc->getData()->errorListen.findDelete(this);
			mtx.release();
			trc->getData()->listenerLock.release();
		}
	}

/*------------------------------------------------------------
     Error Sender
 ------------------------------------------------------------*/

	//Error destructor
	errorSender::~errorSender()
	{
		listenerLock.acquire();
		errorListen.resetTraverse();
		for(auto trc=errorListen.getFirst();trc;trc=trc->getNext())
		{
			trc->getData()->mtx.acquire();
			trc->getData()->senders.findDelete(this);
			trc->getData()->mtx.release();
		}
		listenerLock.release();
	}
	//Pushes error listeners onto the sender
	void errorSender::pushErrorListener(os::smart_ptr<errorListener> listener)
	{
		if(!listener) return;
		listenerLock.acquire();
		listener->mtx.acquire();

		errorListen.insert(listener);
		listener->senders.insert(this);

		listener->mtx.release();
		listenerLock.release();
	}
	//Remove error listener from the sender
	void errorSender::removeErrrorListener(os::smart_ptr<errorListener> listener)
	{
		if(!listener) return;
		listenerLock.acquire();
		listener->mtx.acquire();

		errorListen.findDelete(listener);
		listener->senders.findDelete(this);

		listener->mtx.release();
		listenerLock.release();
	}
	//Logs the error
	void errorSender::logError(errorPointer elm)
	{
		listenerLock.acquire();
		errorLog.insert(elm);
		if(errorLog.size()>_logLength) errorLog.findDelete(errorLog.getFirst()->getData());
		
		errorListen.resetTraverse();
		for(auto trc=errorListen.getFirst();trc;trc=trc->getNext())
		{
			trc->getData()->mtx.acquire();
			trc->getData()->receiveError(elm,this);
			trc->getData()->mtx.release();
		}
		listenerLock.release();
	}
	//Pop an error
	errorPointer errorSender::popError()
	{
		listenerLock.acquire();
		errorPointer ptr=errorLog.getFirst()->getData();
		errorLog.findDelete(ptr);
		listenerLock.release();
		return ptr;
	}
	//Set the log length
	void errorSender::setLogLength(unsigned int logLength)
	{
		if(logLength<1) return;

		listenerLock.acquire();
		_logLength=logLength;

		while(errorLog.size()>logLength)
			errorLog.findDelete(errorLog.getFirst()->getData());

		listenerLock.release();
	}
}

#endif

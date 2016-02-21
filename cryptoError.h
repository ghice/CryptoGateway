//Primary author: Jonathan Bedard
//Certified working 2/19/2016

#ifndef CRYPTO_ERROR_H
#define CRYPTO_ERROR_H
 
#include "streamPackage.h"
#include "file_mechanics.h"
#include "cryptoLogging.h"
#include "osMechanics.h"

namespace crypto {

	//Base error class
	class error: public virtual os::ptrComp, public std::exception
	{
		uint64_t _timestamp;
		std::string whatString;
	public:
		error(){_timestamp=get_timestamp();}
		virtual ~error() throw() {}

		inline virtual std::string errorTitle() const {return "Error";}
		inline virtual std::string errorDescription() const {return "No description";}
		std::string timestampString() const {return convertTimestamp(_timestamp);}
		void log() const {cryptoerr<<errorTitle()<<" on "<<timestampString()<<" : "<<errorDescription()<<std::endl;}

		uint64_t timestamp() const {return _timestamp;}
		const char* what() const throw()
		{
			error* e=(error*) this;	//Bad practice, but the nature of this class makes this needed
			e->whatString=errorTitle()+" on "+timestampString()+" : "+errorDescription();
			return whatString.c_str();
		}
	};
	typedef os::smart_ptr<error> errorPointer;
	
	class passwordSmallError: public error
	{
	public:
		virtual ~passwordSmallError() throw() {}
		inline std::string errorTitle() const {return "Password Size Error";}
		inline std::string errorDescription() const {return "Password too small";}
	};
	class passwordLargeError: public error
	{
	public:
		virtual ~passwordLargeError() throw() {}
		inline std::string errorTitle() const {return "Password Size Error";}
		inline std::string errorDescription() const {return "Password too large";}
	};
	
	class bufferSmallError: public error
	{
	public:
		virtual ~bufferSmallError() throw() {}
		inline std::string errorTitle() const {return "Buffer Size Error";}
		inline std::string errorDescription() const {return "Buffer too small";}
	};
	class bufferLargeError: public error
	{
	public:
		virtual ~bufferLargeError() throw() {}
		inline std::string errorTitle() const {return "Buffer Size Error";}
		inline std::string errorDescription() const {return "Buffer too large";}
	};
	class insertionFailed: public error
	{
	public:
		virtual ~insertionFailed() throw() {}
		inline std::string errorTitle() const {return "Insertion Failed";}
		inline std::string errorDescription() const {return "Insertion into an abstract data-structure unexpectedly failed";}
	};

	class customError: public error
	{
		std::string _name;
		std::string _description;
	public:
		customError(std::string name, std::string description)
		{
			_name=name;
			_description=description;
		}
		virtual ~customError() throw() {}
		inline std::string errorTitle() const {return _name;}
		inline std::string errorDescription() const {return _description;}
	};

	class fileOpenError: public error
	{
	public:
		virtual ~fileOpenError() throw() {}
		std::string errorTitle() const {return "File Open Error";}
		std::string errorDescription() const {return "Cannot open the specified file";}
	};
	class fileFormatError: public error
	{
	public:
		virtual ~fileFormatError() throw() {}
		std::string errorTitle() const {return "File Format Error";}
		std::string errorDescription() const {return "The file is not of the specified format, and an error resulted";}
	};
	class illegalAlgorithmBind: public error
	{
		std::string algorithmName;
	public:
		virtual ~illegalAlgorithmBind() throw() {}
		illegalAlgorithmBind(std::string algoName){algorithmName=algoName;}
		std::string errorTitle() const {return "Illegal Algorithm Bind";}
		std::string errorDescription() const {return "Cannot bind algorithm of type: "+algorithmName;}
	};
	class hashCompareError: public error
	{
	public:
		virtual ~hashCompareError() throw() {}
		std::string errorTitle() const {return "Hash Compare";}
		std::string errorDescription() const {return "Provided and calculated hashes do not match";}
	};
	class hashGenerationError: public error
	{
	public:
		virtual ~hashGenerationError() throw() {}
		std::string errorTitle() const {return "Hash Generation";}
		std::string errorDescription() const {return "Could not generate a hash with the given arguments";}
	};

	class actionOnFileError: public error
	{
	public:
		virtual ~actionOnFileError() throw() {}
		std::string errorTitle() const {return "Action on File Error";}
		std::string errorDescription() const {return "Cannot preform action on a file in the error state.";}
	};
	class actionOnFileClosed: public error
	{
	public:
		virtual ~actionOnFileClosed() throw() {}
		std::string errorTitle() const {return "Action on File Closed";}
		std::string errorDescription() const {return "Cannot preform action on a file in the closed state.";}
	};

	class publicKeySizeWrong: public error
	{
	public:
		virtual ~publicKeySizeWrong() throw() {}
		std::string errorTitle() const {return "Public Key Size Wrong";}
		std::string errorDescription() const {return "Attempted to use a code or n of impropper size";}
	};
	class NULLPublicKey: public error
	{
	public:
		virtual ~NULLPublicKey() throw() {}
		std::string errorTitle() const {return "Public Key NULL";}
		std::string errorDescription() const {return "Attempted to bind a public key of illegal type NULL";}
	};
	class NULLDataError: public error
	{
	public:
		virtual ~NULLDataError() throw() {}
		std::string errorTitle() const {return "NULL Data";}
		std::string errorDescription() const {return "A function was passed NULL data where this is illegal";}
	};
	class NULLMaster: public error
	{
	public:
		virtual ~NULLMaster() throw() {}
		std::string errorTitle() const {return "NULL Master pointer";}
		std::string errorDescription() const {return "A class received a NULL master pointer, this is illegal.";}
	};
	class masterMismatch: public error
	{
	public:
		virtual ~masterMismatch() throw() {}
		std::string errorTitle() const {return "Master Comparison Mis-match";}
		std::string errorDescription() const {return "Two nodes which are interacting have different masters!";}
	};
	class unknownErrorType: public error
	{
	public:
		virtual ~unknownErrorType() throw() {}
		std::string errorTitle() const {return "Unknown Error Type";}
		std::string errorDescription() const {return "Caught some exception, but the type is unknown";}
	};

	//Error Listener
	class errorSender;
	class errorListener: public virtual os::ptrComp
	{
	private:
		friend class errorSender;
		os::spinLock mtx;
		os::smartSet<errorSender> senders;
	public:
		virtual ~errorListener();
		virtual void receiveError(errorPointer elm,os::smart_ptr<errorSender> source){}
	};

	//Error sender
	class errorSender: public virtual os::ptrComp
	{
		friend class errorListener;
		os::spinLock listenerLock; //Shouldn't need
		os::smartSet<errorListener> errorListen;

		os::unsortedList<error> errorLog;
		unsigned int _logLength;
	protected:
		void logError(errorPointer elm);
	public:
		errorSender(){_logLength=20;}
		virtual ~errorSender();

		void pushErrorListener(os::smart_ptr<errorListener> listener);
		void removeErrrorListener(os::smart_ptr<errorListener> listener);

		errorPointer popError();

		void setLogLength(unsigned int logLength);
		unsigned int logLength() const {return _logLength;}
	};
};

#endif

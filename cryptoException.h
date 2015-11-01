//Primary author: Jonathan Bedard
//Confirmed working: 11/1/2015

#ifndef CRYPTO_EXCEPTION_H
#define CRYPTO_EXCEPTION_H

#include <string>
#include <exception>

namespace crypto
{
    //General exception
    class cryptoException: public std::exception
    {
    private:
        std::string location;
        std::string _error;
        std::string total_error;
    public:
        cryptoException(std::string err, std::string loc="")
        {
            location = loc;
            _error = err;
            if(loc!="")
                total_error = err+", "+loc;
            else
                total_error = err;
        }
        virtual const char* what() const throw(){return total_error.c_str();}
        const std::string& getLocation() const {return location;}
        const std::string& getString() const {return _error;}
    };
}

#endif
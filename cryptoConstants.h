//Primary author: Jonathan Bedard
//Confirmed working: 12/6/2015

#ifndef CRYPTOCONSTANTS_H
#define CRYPTOCONSTANTS_H

#include "C_Algorithms/cryptoCConstants.h"

#include <string>

//Scoped C++ variables
namespace crypto
{
	namespace numberType
	{
		extern const int Default;
		extern const int Base10;
	}
	namespace numberName
	{
		extern const std::string Default;
		extern const std::string Base10;
	}
}

#endif
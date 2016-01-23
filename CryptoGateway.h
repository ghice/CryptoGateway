//Primary author: Jonathan Bedard
//Confirmed working: 1/22/2016

#ifndef CRYPTOGATEWAY_H
#define CRYPTOGATEWAY_H

namespace crypto
{
	extern bool global_logging;
}

#include "cryptoLogging.h"
#include "file_mechanics.h"
#include "interior_message.h"
#include "large_number.h"
#include "public_key.h"
#include "streamCipher.h"
#include "RC4_Hash.h"

#include "security_gateway.h"

#include "binaryEncryption.h"
#include "XMLEncryption.h"

#include "streamPackage.h"

#include "cryptoPublicKey.h"

#endif
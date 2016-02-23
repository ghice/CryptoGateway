/**
 * @file	CryptoGateway.h
 * @author	Jonathan Bedard
 * @date   	2/22/2016
 * @brief	Global include file
 * @bug	None
 *
 * This file contains all of the
 * headers in the CryptoGateway
 * library.  Project which depend
 * on the CryptoGateway library
 * need only include this file.
 **/

#ifndef CRYPTOGATEWAY_H
#define CRYPTOGATEWAY_H

namespace crypto
{
	/** @brief Deprecated logging flag
	 */
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
#include "keyBank.h"

#endif
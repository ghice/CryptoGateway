//Primary author: Jonathan Bedard
//Confirmed working: 1/24/2016

#ifndef TEST_KEY_GENERATION_CPP
#define TEST_KEY_GENERATION_CPP

#include "testKeyGeneration.h"

namespace test
{
	//Finding static keys
	void findKeysRaw(uint32_t*& nPtr,uint32_t*& dPtr,uint16_t algoID,uint16_t keySize,unsigned int version)
	{
		//RSA case
		if(algoID==crypto::algo::publicRSA)
		{
			//Split into 4 case
			if(keySize==crypto::size::public256)
			{
				if(version)
				{
					nPtr=(uint32_t*)crypto::constant::keys_256::n_2;
					dPtr=(uint32_t*)crypto::constant::keys_256::d_2;
				}
				else
				{
					nPtr=(uint32_t*)crypto::constant::keys_256::n_1;
					dPtr=(uint32_t*)crypto::constant::keys_256::d_1;
				}
			}
			else if(keySize==crypto::size::public512)
			{
				if(version)
				{
					nPtr=(uint32_t*)crypto::constant::keys_512::n_2;
					dPtr=(uint32_t*)crypto::constant::keys_512::d_2;
				}
				else
				{
					nPtr=(uint32_t*)crypto::constant::keys_512::n_1;
					dPtr=(uint32_t*)crypto::constant::keys_512::d_1;
				}
			}
			else if(keySize==crypto::size::public1024)
			{
				if(version)
				{
					nPtr=(uint32_t*)crypto::constant::keys_1024::n_2;
					dPtr=(uint32_t*)crypto::constant::keys_1024::d_2;
				}
				else
				{
					nPtr=(uint32_t*)crypto::constant::keys_1024::n_1;
					dPtr=(uint32_t*)crypto::constant::keys_1024::d_1;
				}
			}
			else if(keySize==crypto::size::public2048)
			{
				if(version)
				{
					nPtr=(uint32_t*)crypto::constant::keys_2048::n_2;
					dPtr=(uint32_t*)crypto::constant::keys_2048::d_2;
				}
				else
				{
					nPtr=(uint32_t*)crypto::constant::keys_2048::n_1;
					dPtr=(uint32_t*)crypto::constant::keys_2048::d_1;
				}
			}
			else throw os::smart_ptr<std::exception>(new generalTestException("Illegal public key size: "+std::to_string(keySize*32),"testKeyGeneration.h, void findKeys(...)"),os::shared_type);
		}
		else throw os::smart_ptr<std::exception>(new generalTestException("Requested algorithm is not a public key algorithm","testKeyGeneration.h, void findKeys(...)"),os::shared_type);
	}
};

#endif
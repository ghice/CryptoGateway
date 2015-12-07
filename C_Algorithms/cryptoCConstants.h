//Primary author: Jonathan Bedard
//Confirmed working: 12/6/2015

#ifndef CRYPTO_C_CONSTANTS_H
#define CRYPTO_C_CONSTANTS_H

#ifdef __cplusplus
extern "C" {
#endif

//Some constants must be visible from C
extern const int crypto_numbertype_default;
extern const int crypto_numbertype_base10;

extern const char* crypto_numbername_default;
extern const char* crypto_numbername_base10;

#ifdef __cplusplus
}
#endif

#endif
//Primary author: Jonathan Bedard
//Confirmed working 10/11/2014

#ifndef SECURITY_GATEWAY_H
#define SECURITY_GATEWAY_H

#include <string>
#include <iostream>
#include <stdlib.h>

#include "interior_message.h"
#include "public_key.h"
#include "streamCode.h"
#include "RC4.h"
#include "RC4_Hash.h"

#define ID_SIZE 20
#define TIMEOUT_VALUE 30

class security_gateway
{
private:
  public_key_base* crypto_base;
  streamDecrypter* decryp;
  streamEncrypter* encry;
  
  interior_message identifier_message;
  interior_message error_message;
  interior_message key_confirmation;
  interior_message* RC_key_message;
  
  bool gateway_active;
  bool initial_message;
  bool connection_signed;
  
  bool error;
  bool crypto_error;
  uint64_t crypto_error_stamp;
  
  uint8_t connection_type;
  uint64_t last_timestamp;
  
  uint8_t current_status;
  char system_ID[ID_SIZE];
  
  uint8_t brother_status;
  char brother_ID[ID_SIZE];
  bool key_coded;
  large_integer brother_key;
  
  large_integer old_brother_key;
  bool brother_key_set;
  
  //Private Functions
  void build_encryption_stream();
  void push_timestamp_initialize(interior_message* msg);
  
public:
  //Constructor data
  security_gateway();
  security_gateway(public_key_base* key_source, uint8_t type, char* ID);
 virtual  ~security_gateway();
  void push_data(public_key_base* key_source, uint8_t type, char* ID);
  
  //Public Actions
  void reset();
  void push_old_key(uint8_t* byte, int length);
  void push_old_key(large_integer key);
  void force_error();
  void force_crypto_error();
  
  //Get Functions
  bool is_active();
  bool connected();
  uint64_t get_time_dif();
  interior_message* get_message();
  bool process_message(interior_message* msg);
  interior_message* encrypt_message(interior_message* msg);
  large_integer getBrotherKey();
  large_integer getOldBrotherKey();
};

#endif

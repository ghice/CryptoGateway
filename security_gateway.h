//Primary author: Jonathan Bedard
//Confirmed working: 1/9/2016

#ifndef SECURITY_GATEWAY_H
#define SECURITY_GATEWAY_H

#include <string>
#include <iostream>
#include <stdlib.h>

#include "securitySpinLock.h"
#include "interior_message.h"
#include "public_key.h"
#include "streamCipher.h"
#include "RC4_Hash.h"
#include "file_mechanics.h"

namespace crypto {

#define GROUP_SIZE 20
#define ID_SIZE 20
#define TIMEOUT_VALUE 15
extern bool global_logging;

class security_gateway
{
private:
  os::smart_ptr<public_key_base> crypto_base;

  sgSpinLock decrypLock;
  sgSpinLock encryLock;
  os::smart_ptr<streamDecrypter> decryp;
  os::smart_ptr<streamEncrypter> encry;
  
  interior_message identifier_message;
  interior_message error_message;
  interior_message key_confirmation;
  smartInteriorMessage RC_key_message;
  
  bool gateway_active;
  bool initial_message;
  bool connection_signed;
  
  uint8_t last_message_type;
  bool error;
  bool crypto_error;
  uint64_t crypto_error_stamp;
  
  uint8_t connection_type;
  uint64_t last_timestamp;
  
  uint8_t current_status;
  char target_group[GROUP_SIZE];
  char system_ID[ID_SIZE];
  
  uint8_t brother_status;
  sgSpinLock brotherIDLock;
  char brother_ID[ID_SIZE];
  bool key_coded;
  sgSpinLock brotherKeyLock;
  large_integer brother_key;
  
  sgSpinLock oldBrotherKeyLock;
  large_integer old_brother_key;
  bool brother_key_set;
  
  //Private Functions
  void build_encryption_stream();
  void push_timestamp_initialize(interior_message& msg);
  
public:
  //Constructor data
  security_gateway();
  security_gateway(os::smart_ptr<public_key_base> key_source, uint8_t type, const char* group_id, const char* ID);
 virtual  ~security_gateway();
  void push_data(os::smart_ptr<public_key_base> key_source, uint8_t type, const char* group_id, const char* ID);
  
  //Public Actions
  void reset();
  void push_old_key(uint8_t* b, int length);
  void push_old_key(large_integer key);
  void force_error();
  void force_crypto_error();
  
  //Get Functions
  bool is_active();
  bool connected();
  uint64_t get_time_dif();
  smartInteriorMessage get_message();
  bool process_message(smartInteriorMessage msg);
  smartInteriorMessage encrypt_message(smartInteriorMessage msg);
  const large_integer getBrotherKey();
  const large_integer getOldBrotherKey();
  os::smart_ptr<public_key_base> getPublicKey();
  uint8_t getBrotherStatus();
  uint8_t getMyStatus();
  std::string getBrotherID();
  std::string getGroupID() const {return std::string(target_group);}
};
    
}

#endif

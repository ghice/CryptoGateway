//Primary author: Jonathan Bedard
//Confirmed working: 9/12/2015

/*
	NOTE: This file may have endian problems
*/

#ifndef SECURITY_GATEWAY_CPP
#define SECURITY_GATEWAY_CPP

#include <string>
#include <iostream>
#include <stdlib.h>

#include "cryptoLogging.h"
#include "file_mechanics.h"
#include "interior_message.h"
#include "public_key.h"
#include "streamCode.h"
#include "RC4.h"

#include "security_gateway.h"

#define MESSAGE_INITIAL 0
#define MESSAGE_EXCHANGE_STREAM 1
#define MESSAGE_SIGN 2
#define MESSAGE_PING 3
#define MESSAGE_DECRYPT 4
#define MESSAGE_CONFIRM_OLD 5

#define MESSAGE_CRYPTO_ERROR 253
#define MESSAGE_ERROR_CONFIRM 254
#define MESSAGE_ERROR 255

using namespace std;
using namespace crypto;

//Constructors-------------------------------------------------------------------

//Basic constructor
security_gateway::security_gateway()
{
  error = false;
  crypto_error = false;
  gateway_active = false;
  initial_message = false;
  connection_signed = false;
  key_coded = false;
  brother_key_set = false;
    
  last_message_type = MESSAGE_INITIAL;
  
  connection_type = 0;
  current_status = 0;
  brother_status = 0;
  
  last_timestamp = 0;
  
  encry = NULL;
  decryp = NULL;
  RC_key_message = smartInteriorMessage(new interior_message);
  
  int cnt = 0;
  while(cnt<ID_SIZE)
  {
    system_ID[cnt] = '\0';
    brother_ID[cnt] = '\0';
    cnt++;
  }
  cnt = 0;
  while(cnt<GROUP_SIZE)
  {
    target_group[cnt] = '\0';
    cnt++;
  }
}
//Complete constructor
security_gateway::security_gateway(public_key_base* key_source, uint8_t type, const char* group_id, const char* ID)
{
  error = false;
  crypto_error = false;
  initial_message = false;
  connection_signed = false;
  key_coded = false;
  brother_key_set = false;
  
  last_message_type = MESSAGE_INITIAL;
    
  connection_type = 0;
  current_status = 0;
  brother_status = 0;
  
  last_timestamp = 0;
  
  encry = NULL;
  decryp = NULL;
  RC_key_message = smartInteriorMessage(new interior_message);
  
  //Set brother ID to NULL
  int cnt = 0;
  while(cnt<ID_SIZE)
  {
    brother_ID[cnt] = '\0';
    cnt++;
  }
  
  push_data(key_source,type,group_id,ID);
}
//Destructor
security_gateway::~security_gateway()
{
  //Note: do not delete the crypto base, it is shared
  decrypLock.acquire();
  if(decryp!=NULL)
    delete(decryp);
  decrypLock.release();
    
  encryLock.acquire();
  if(encry!=NULL)
    delete(encry);
  encryLock.release();
}
//Initialize data
void security_gateway::push_data(public_key_base* key_source, uint8_t type, const char* group_id, const char* ID)
{
  int cnt = 0;
  //Reset the system ID
  while(cnt<ID_SIZE)
  {
    system_ID[cnt] = '\0';
    cnt++;
  }
  //Reset the group ID
  cnt = 0;
  while(cnt<GROUP_SIZE)
  {
    target_group[cnt] = '\0';
    cnt++;
  }
  
  //Set the public key interface
  crypto_base = key_source;
  
  //Set the current status (no connection)
  current_status = 0;
  connection_type = type;
  
  build_encryption_stream();
  
  //Copy the system ID
  cnt = 0;
  while(cnt<ID_SIZE && ID[cnt]!='\0')
  {
    system_ID[cnt] = ID[cnt];
    cnt++;
  }
  //Copy the group ID
  cnt=0;
  while(cnt<GROUP_SIZE && group_id[cnt]!='\0')
  {
      target_group[cnt]=group_id[cnt];
      cnt++;
  }
  //Builds the identifier
  uint8_t* temp_array = identifier_message.get_int_data();
  
  //Message header
  temp_array[0] = 0;
  temp_array[1] = 0;
  temp_array[2] = 0;
  temp_array[3] = 0;
  
  //Copy in the group ID and system ID
  cnt = 4;
  while(cnt<GROUP_SIZE+4)
  {
    temp_array[cnt] = target_group[cnt-4];
    cnt++;
  }
  while(cnt<GROUP_SIZE+ID_SIZE+4)
  {
    temp_array[cnt] = system_ID[cnt-4-GROUP_SIZE];
    cnt++;
  }
  
  //Skip pointer ahead
  cnt = 0;
  uint8_t* ptr = temp_array;
  while(cnt<4+GROUP_SIZE+ID_SIZE+8)
  {
    ptr++;
    cnt++;
  }
  
  //Plublish the public key_source
  large_integer pub_key = crypto_base->get_n();
  cnt = 0;
  uint32_t* trc = (uint32_t*) ptr;
  while(cnt<LARGE_NUMBER_SIZE/2)
  {
	  trc[cnt] = to_comp_mode_sgtw(pub_key.getArrayNumber(cnt));
      cnt++;
  }
  
  //Set identifier message size
  identifier_message.push_length(4+GROUP_SIZE+ID_SIZE+8+LARGE_NUMBER_SIZE*2);
  
  //Sets the gateway to active
  gateway_active = true;
}

//Private Functions--------------------------------------------------------------

//Builds and initializes the encryption stream
void security_gateway::build_encryption_stream()
{
  //Reset variables
  current_status = 0;
  initial_message = false;
  key_coded = false;
  
  //Initialize message
  RC_key_message->push_length(LARGE_NUMBER_SIZE*2+4);
  //Construct the stream encrypter, with message constructing in mind
  uint8_t* RC4_array = RC_key_message->get_int_data();
  int cnt = 4;
  
  //Message type
  RC4_array[0] = 1;
  //My status (to be set later)
  RC4_array[1] = 0;
  //NULL
  RC4_array[2] = 0;
  RC4_array[3] = 0;
  srand(time(NULL));

  //Randomly set the key
  while(cnt<LARGE_NUMBER_SIZE*2+4)
  {
	RC4_array[cnt] = (uint8_t) (rand());
    cnt++;
  }
    
  //Zero out last few bytes
  RC4_array[LARGE_NUMBER_SIZE*2]=0;
  RC4_array[LARGE_NUMBER_SIZE*2+1]=0;
  RC4_array[LARGE_NUMBER_SIZE*2+2]=0;
  RC4_array[LARGE_NUMBER_SIZE*2+3]=0;
  
  encryLock.acquire();
  if(encry!=NULL)
    delete(encry);
  RCFour* temp_RC4 = new RCFour(&RC4_array[4],LARGE_NUMBER_SIZE*2-1);
  encry = new streamEncrypter(temp_RC4);
  encryLock.release();
}
//Places the proper timestamp on 
void security_gateway::push_timestamp_initialize(interior_message& msg)
{
  uint8_t* temp_array = msg.get_int_data();
  uint64_t timestamp = get_timestamp();
  timestamp = to_comp_mode_sgtw(timestamp);
  uint8_t* timestamp_ptr = (uint8_t*) &timestamp;
  int cnt = 0;
  
  while(cnt<8)
  {
    temp_array[4+GROUP_SIZE+ID_SIZE+cnt] = timestamp_ptr[cnt];
    cnt++;
  }
}

//Public Actions-----------------------------------------------------------------

//Resets the system
void security_gateway::reset()
{
  int cnt = 0;
  while(cnt<ID_SIZE)
  {
    brother_ID[cnt] = '\0';
    cnt++;
  }
  error = false;
  crypto_error = false;
  initial_message = false;
  key_coded = false;
  connection_signed = false;
  connection_type = 0;
  current_status = 0;
  brother_status = 0;
  
  last_timestamp = 0;
  
  decrypLock.acquire();
  if(decryp!=NULL)
      delete decryp;
  decryp = NULL;
  decrypLock.release();
  encryLock.acquire();
  if(encry!=NULL)
      delete encry;
  encry = NULL;
  encryLock.release();
  
  build_encryption_stream();
}
//Push the old key
void security_gateway::push_old_key(uint8_t* b, int length)
{
  int new_len = length/4;
  if(length%4)
    new_len++;
  
  large_integer temp((uint32_t*)b, new_len);
  push_old_key(temp);
}
//Push the old key
void security_gateway::push_old_key(large_integer key)
{
  oldBrotherKeyLock.acquire();
  old_brother_key = key;
  oldBrotherKeyLock.release();
  brother_key_set = true;
}
//Triggers an error in the gateway
void security_gateway::force_error()
{
  error = true;
}
//Triggers a crypto error
void security_gateway::force_crypto_error()
{
  crypto_error = true;
  crypto_error_stamp = get_timestamp();
}

//Get Functions------------------------------------------------------------------

//Return if the gateway is active
bool security_gateway::is_active()
{
  return gateway_active;
}
bool security_gateway::connected()
{
  if(connection_signed && !error && !crypto_error && brother_status!=255 && brother_status>=3)
    return true;
  return false;
}
//Return the time from the last message
uint64_t security_gateway::get_time_dif()
{
  if(last_timestamp==0)
    return 0;
  return (get_timestamp()-last_timestamp);
}
//Return the current message
smartInteriorMessage security_gateway::get_message()
{
  //Send a null message if the gateway is not active
  if(!gateway_active)
  {
	return smartInteriorMessage(NULL);
  }
  
  uint8_t* temp;
  
  //Send the crypto error message
  if(crypto_error)
  {
    if((get_timestamp()-crypto_error_stamp)>TIMEOUT_VALUE)
    {
      crypto_error = false;
      reset();
    }
    
    uint8_t* err = error_message.get_int_data();
    err[0] = MESSAGE_CRYPTO_ERROR;
    err[1] = 255;
    err[2] = 0;
    err[3] = 0;
    error_message.push_length(4);
    return smartInteriorMessage(new interior_message(error_message));
  }
  //No connection received
  if(brother_status == 0 && !error)
  {
    identifier_message.get_int_data()[0] = MESSAGE_INITIAL;
    identifier_message.get_int_data()[1] = current_status;
    push_timestamp_initialize(identifier_message);
    return smartInteriorMessage(new interior_message(identifier_message));
  }
  //Initial connection made, trade keys
  if(brother_status == 1 && !error)
  {
    //This gateway has received the initial message
    if(initial_message)
    {
      RC_key_message->get_int_data()[0] = MESSAGE_EXCHANGE_STREAM;
      RC_key_message->get_int_data()[1] = current_status;
      //Encrypt the message, only once
      if(!key_coded)
      {
		key_coded = true;
		temp = RC_key_message->get_int_data();
        brotherKeyLock.acquire();
		crypto_base->encode((char*)&temp[4],LARGE_NUMBER_SIZE*2,brother_key);
        brotherKeyLock.release();
      }
      return RC_key_message;
    }
    //This gateway has not received the intial message, request it
    else
    {
      identifier_message.get_int_data()[0] = MESSAGE_INITIAL;
      identifier_message.get_int_data()[1] = current_status;
      push_timestamp_initialize(identifier_message);
      return smartInteriorMessage(new interior_message(identifier_message));
    }
  }
  //Keys exchanged, attempt to sign
  if(brother_status == 2 && !error)
  {
    temp = key_confirmation.get_int_data();

	//Reset confirmation structure
	int reset_cnt = 0;
	while(reset_cnt<key_confirmation.get_full_length())
	{
		temp[reset_cnt] = 0;
		reset_cnt++;
	}

    key_confirmation.push_length(12+LARGE_NUMBER_SIZE*2);
    temp[0] = MESSAGE_SIGN;
    temp[1] = current_status;
    
    //Copy timestamps
    uint64_t timestamp = get_timestamp();
	timestamp = to_comp_mode_sgtw(timestamp);
    uint8_t* stmp = (uint8_t*) &timestamp;
    temp[4] = stmp[0];
    temp[5] = stmp[1];
    temp[6] = stmp[2];
    temp[7] = stmp[3];
    temp[8] = stmp[0];
    temp[9] = stmp[1];
    temp[10] = stmp[2];
    temp[11] = stmp[3];
    
    int temp_cnt = 0;
    
    //Copy this sytem ID
    while(temp_cnt<ID_SIZE)
    {
      temp[12+temp_cnt] = system_ID[temp_cnt];
      temp_cnt++;
    }
    temp_cnt = 0;
    //Copy the brother ID
    brotherIDLock.acquire();
    while(temp_cnt<ID_SIZE)
    {
      temp[12+ID_SIZE+temp_cnt] = brother_ID[temp_cnt];
      temp_cnt++;
    }
    brotherIDLock.release();
    
    //Run hash function
    hash_256 hash = build_hash((char*) &temp[8],4+ID_SIZE*2);
    temp_cnt = 0;
    while(temp_cnt<BYTE_SIZE_HASH)
    {
      temp[8+temp_cnt] = (uint8_t) hash.get_hash()[temp_cnt];
      temp_cnt++;
    }
    while(temp_cnt<4+2*ID_SIZE)
    {
      temp[8+temp_cnt] = 0;
      temp_cnt++;
    }
    
    //Sign the hash
    crypto_base->decode((char*)&temp[8],LARGE_NUMBER_SIZE*2);

    uint16_t stream_flag;
    encryLock.acquire();
    encry->sendData(&temp[4],8+LARGE_NUMBER_SIZE*2,(uint16_t*) &stream_flag);
    encryLock.release();
    temp[2] = (stream_flag>>8);
    temp[3] = (uint8_t) stream_flag;

    return smartInteriorMessage(new interior_message(key_confirmation));
  }
  //Send a message indicating continued connection but no information
  if(brother_status == 3 && !error)
  {
    uint8_t* err = error_message.get_int_data();
    err[0] = MESSAGE_PING;
    err[1] = current_status;
    err[2] = 0;
    err[3] = 0;
    error_message.push_length(4);
    return smartInteriorMessage(new interior_message(error_message));
  }
  //Sign with the old key
  if(brother_status == 4 && !error)
  {
    temp = key_confirmation.get_int_data();

	//Reset confirmation structure
	int reset_cnt = 0;
	while(reset_cnt<key_confirmation.get_full_length())
	{
		temp[reset_cnt] = 0;
		reset_cnt++;
	}

    key_confirmation.push_length(8+LARGE_NUMBER_SIZE*2);
    temp[0] = MESSAGE_CONFIRM_OLD;
    temp[1] = current_status;
    
    //Copy timestamps
    uint64_t timestamp = get_timestamp();
	timestamp = to_comp_mode_sgtw(timestamp);
    uint8_t* stmp = (uint8_t*) &timestamp;
    temp[4] = stmp[0];
    temp[5] = stmp[1];
    temp[6] = stmp[2];
    temp[7] = stmp[3];
    temp[8] = stmp[0];
    temp[9] = stmp[1];
    temp[10] = stmp[2];
    temp[11] = stmp[3];
    
    int temp_cnt = 0;
    
    //Copy this sytem ID
    while(temp_cnt<ID_SIZE)
    {
      temp[12+temp_cnt] = system_ID[temp_cnt];
      temp_cnt++;
    }
    temp_cnt = 0;
    //Copy the brother ID
    brotherIDLock.acquire();
    while(temp_cnt<ID_SIZE)
    {
      temp[12+ID_SIZE+temp_cnt] = brother_ID[temp_cnt];
      temp_cnt++;
    }
    brotherIDLock.release();
    
    //Run hash function
    hash_256 hash = build_hash((char*) &temp[8],4+ID_SIZE*2);
    temp_cnt = 0;
    while(temp_cnt<BYTE_SIZE_HASH)
    {
      temp[8+temp_cnt] = (uint8_t) hash.get_hash()[temp_cnt];
      temp_cnt++;
    }
    while(temp_cnt<4+2*ID_SIZE)
    {
      temp[8+temp_cnt] = 0;
      temp_cnt++;
    }
    
    //Sign the hash
    crypto_base->old_decode((char*)&temp[8],LARGE_NUMBER_SIZE*2);

    uint16_t stream_flag;
    encryLock.acquire();
    encry->sendData(&temp[4],8+LARGE_NUMBER_SIZE*2,(uint16_t*) &stream_flag);
    encryLock.release();
    temp[2] = (stream_flag>>8);
    temp[3] = (uint8_t) stream_flag;

    return smartInteriorMessage(new interior_message(key_confirmation));
  }
  //Confirm brother's error status
  if(brother_status == 255 && !error)
  {
    uint8_t* err = error_message.get_int_data();
    err[0] = MESSAGE_ERROR_CONFIRM;
    err[1] = current_status;
    err[2] = 0;
    err[3] = 0;
    error_message.push_length(4);
    return smartInteriorMessage(new interior_message(error_message));
  }
  
  //Return error message
  uint8_t* err = error_message.get_int_data();
  err[0] = MESSAGE_ERROR;
  err[1] = current_status;
  err[2] = 0;
  err[3] = 0;
  error_message.push_length(4);
  return smartInteriorMessage(new interior_message(error_message));
}
//Processes the message
bool security_gateway::process_message(smartInteriorMessage msg)
{
  //Check for error status
  if(!msg)
    return false;

  int cnt = 4;
  
  //Check the status
  uint8_t* message_array = msg->get_int_data();
  uint8_t message_type = message_array[0];
  uint16_t stream_flag = (((uint16_t) message_array[2])<<8)^message_array[3];
  brother_status = message_array[1];
    
  //Crypto error
  if(message_type==MESSAGE_CRYPTO_ERROR)
  {
    reset();
    last_timestamp = get_timestamp();
    return false;
  }
  
  //Brother confirmed your error
  if(message_type==MESSAGE_ERROR_CONFIRM)
  {
    reset();
    
    last_timestamp = get_timestamp();
    return true;
  }
  
  //Brother has thrown an error, reset
  if(message_type==MESSAGE_ERROR)
  {
    reset();
    brother_status = 255;
    
    last_timestamp = get_timestamp();
    return true;
  }
  
  //Initial message
  if(message_type==MESSAGE_INITIAL)
  {
    //First process
    if(!initial_message)
    {
      initial_message = true;
      current_status = 1;
      
      //Process Group
      char received_id[GROUP_SIZE];
      while(cnt<GROUP_SIZE+4)
      {
          received_id[cnt-4]=message_array[cnt];
          cnt++;
      }
      if(std::string(received_id) != std::string(target_group))
        return false;
        
      //Process ID
      brotherIDLock.acquire();
      while(cnt<ID_SIZE+GROUP_SIZE+4)
      {
		brother_ID[cnt-GROUP_SIZE-4] = message_array[cnt];
		cnt++;
      }
      brotherIDLock.release();
      
      //Process timestamp
      uint64_t* msg_timestamp = (uint64_t*) &message_array[cnt];
	  *msg_timestamp = from_comp_mode_sgtw(*msg_timestamp);

	  uint64_t tmstp = get_timestamp()+TIMEOUT_VALUE;
      if(msg_timestamp[0]>tmstp||tmstp-msg_timestamp[0]>2*TIMEOUT_VALUE)
      {
		error = true;
      }
      
	  *msg_timestamp = to_comp_mode_sgtw(*msg_timestamp);
      //Process public key
      brotherKeyLock.acquire();
      brother_key.push_array_comp_mode((uint32_t*)&message_array[cnt+8],LARGE_NUMBER_SIZE/2);
      brotherKeyLock.release();
    }
    //Compare with current variables
    else
    {
      //Check ID
      brotherIDLock.acquire();
      while(cnt<ID_SIZE+4)
      {
		if(brother_ID[cnt-4] != message_array[cnt])
		{
		  error = true;
		}
		cnt++;
      }
      brotherIDLock.release();
      //Ignore timestamp
      
      //Check public key
      large_integer hld;
      hld.push_array_comp_mode((uint32_t*)&message_array[cnt+8],LARGE_NUMBER_SIZE/2);
      brotherKeyLock.acquire();
      if(hld!=brother_key)
      {
		error = true;
      }
      brotherKeyLock.release();
    }
    last_timestamp = get_timestamp();
  }
  
  //Exchange stream key
  if(message_type==MESSAGE_EXCHANGE_STREAM && decryp==NULL)
  {
    if(message_type==last_message_type)
        last_timestamp = get_timestamp();
    else
    {
        message_array = &message_array[4];
        crypto_base->decode((char*)message_array,LARGE_NUMBER_SIZE*2);
    
        current_status = 2;
        decrypLock.acquire();
        if(decryp!=NULL)
            delete decryp;
        
        RCFour* rc_temp = new RCFour(message_array, LARGE_NUMBER_SIZE*2-1);
        decryp = new streamDecrypter(rc_temp);
        decrypLock.release();
        last_timestamp = get_timestamp();
    }
  }
  
  //Attempt signatures
  if(message_type==MESSAGE_SIGN)
  {
      //cryptoout<<"Checking signature"<<endl;
    //Test for a valid decryption array
      decrypLock.acquire();
    if(decryp == NULL)
    {
      error = true;
      decrypLock.release();
      return false;
    }

    //Decrypt the array, based on the stream
    if(NULL==decryp->recieveData(&message_array[4],msg->get_length()-4,stream_flag))
    {
      error = true;
      decrypLock.release();
      return false;
    }
    decrypLock.release();
      
    //Just confirmed a signature, don't do it again
    if(message_type==last_message_type)
    {
        return true;
    }
    
    //Build the hash
    uint8_t hash_comp[4+2*ID_SIZE];
    cnt = 0;
    hash_comp[0] = message_array[4];
    hash_comp[1] = message_array[5];
    hash_comp[2] = message_array[6];
    hash_comp[3] = message_array[7];
    brotherIDLock.acquire();
    while(cnt<ID_SIZE)
    {
      hash_comp[4+cnt] = brother_ID[cnt];
      cnt++;
    }
    brotherIDLock.release();
    cnt=0;
    while(cnt<ID_SIZE)
    {
      hash_comp[4+ID_SIZE+cnt] = system_ID[cnt];
      cnt++;
    }
    hash_256 hash = build_hash((char*) hash_comp,4+2*ID_SIZE);
    
    //Decrypt message
    brotherKeyLock.acquire();
    crypto_base->encode((char*)&message_array[8],LARGE_NUMBER_SIZE*2,brother_key);
    brotherKeyLock.release();
      
    //Compare two hashes
    hash_256 inbound((char*)&message_array[8]);
    if(hash!=inbound)
    {
      force_crypto_error();
        //cryptoout<<"Failed 3"<<endl;
      return false;
    }
    
    brotherKeyLock.acquire();
    oldBrotherKeyLock.acquire();
    if(brother_key_set&&old_brother_key!=brother_key)
    {
      brotherKeyLock.release();
      oldBrotherKeyLock.release();
        
      current_status = 4;
      return !(error);
    }
    brotherKeyLock.release();
    oldBrotherKeyLock.release();
    current_status = 3;
    connection_signed = true;
    
    last_timestamp = get_timestamp();
  }
  
  //Continued connection, no action taken
  if(message_type==MESSAGE_PING)
  {
	  last_timestamp = get_timestamp();
  }
  
  //Decrypt the message
  if(message_type==MESSAGE_DECRYPT)
  {
    decrypLock.acquire();
    //Test for a valid decryption array
    if(decryp == NULL || !connection_signed)
    {
      error = true;
      decrypLock.release();
      return false;
    }
    
    //Decrypt the array, based on the stream
    if(NULL==decryp->recieveData(&message_array[4],msg->get_length()-4,stream_flag))
    {
      error = true;
      decrypLock.release();
      return false;
    }
    decrypLock.release();
    last_timestamp = get_timestamp();
  }
  
  //Confirm signature from old key
  if(message_type==MESSAGE_CONFIRM_OLD)
  {
    //Test for a valid decryption array
    decrypLock.acquire();
    if(decryp == NULL)
    {
      error = true;
      decrypLock.release();
      return false;
    }
    
    //Just confirmed a signature, don't do it again
    if(message_type==last_message_type)
    {
        decrypLock.release();
        return true;
    }
      
    //Decrypt the array, based on the stream
    if(NULL==decryp->recieveData(&message_array[4],msg->get_length()-4,stream_flag))
    {
      error = true;
      decrypLock.release();
      return false;
    }
    decrypLock.release();
    
    //Build the hash
    uint8_t hash_comp[4+2*ID_SIZE];
    cnt = 0;
    hash_comp[0] = message_array[4];
    hash_comp[1] = message_array[5];
    hash_comp[2] = message_array[6];
    hash_comp[3] = message_array[7];
    brotherIDLock.acquire();
    while(cnt<ID_SIZE)
    {
      hash_comp[4+cnt] = brother_ID[cnt];
      cnt++;
    }
    brotherIDLock.release();
    cnt=0;
    while(cnt<ID_SIZE)
    {
      hash_comp[4+ID_SIZE+cnt] = system_ID[cnt];
      cnt++;
    }
    hash_256 hash = build_hash((char*) hash_comp,4+2*ID_SIZE);
    
    //Decrypt message
    oldBrotherKeyLock.acquire();
    crypto_base->encode((char*)&message_array[8],LARGE_NUMBER_SIZE*2,old_brother_key);
    oldBrotherKeyLock.release();
    
    //Compare two hashes
    hash_256 inbound((char*)&message_array[8]);
    
    if(hash!=inbound)
    {
      force_crypto_error();
      return false;
    }
    current_status = 3;
    connection_signed = true;
    last_timestamp = get_timestamp();
  }
  
  return (!error);
}
//Encrypt a message based on the security gateway
smartInteriorMessage security_gateway::encrypt_message(smartInteriorMessage msg)
{
  if(!connected())
    return smartInteriorMessage(NULL);
  uint8_t* temp = msg->get_int_data();
  uint16_t stream_flag;
  encryLock.acquire();
  encry->sendData(&temp[4],msg->get_length()-4,(uint16_t*) &stream_flag);
  encryLock.release();
  temp[0] = 4;
  temp[1] = current_status;
  temp[2] = (stream_flag>>8);
  temp[3] = (uint8_t) stream_flag;
  
  return msg;
}
//Returns the brother key
const large_integer security_gateway::getBrotherKey()
{
    brotherKeyLock.acquire();
    large_integer ret = brother_key;
    brotherKeyLock.release();
	return ret;
}
//Returns the old brother key
const large_integer security_gateway::getOldBrotherKey()
{
    oldBrotherKeyLock.acquire();
    large_integer ret = old_brother_key;
    oldBrotherKeyLock.release();
    return ret;
}
//Returns the public key base
public_key_base* security_gateway::getPublicKey()
{
	return crypto_base;
}
//Returns the current brother status
uint8_t security_gateway::getBrotherStatus()
{
	return brother_status;
}
//Returns the current status
uint8_t security_gateway::getMyStatus()
{
	return current_status;
}
//Returns the ID of the brother
std::string security_gateway::getBrotherID()
{
    brotherIDLock.acquire();
    std:string ret = std::string(brother_ID);
    brotherIDLock.release();
    return ret;
}
#endif
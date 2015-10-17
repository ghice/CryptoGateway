//Primary author: Jonathan Bedard
//Certified working 8/29/2015

#ifndef PUBLIC_KEY_CPP
#define PUBLIC_KEY_CPP

#include <string>
#include <iostream>
#include <stdlib.h>
#include "file_mechanics.h"

#include "cryptoLogging.h"
#include "large_number.h"
#include "public_key.h"
#include "streamCode.h"
#include "security_gateway.h"

using namespace std;
using namespace crypto;

//Constructors---------------------------------------------------------------

//Default constructor
public_key_base::public_key_base()
{
  global_file_loc = ".";
  string full_file = "./";
  _username = _password = "";
  full_file = full_file+KEY_FILE_NAME;
  
  uint32_t eArray[1];
  eArray[0] = (1<<16)+1;
  e.push_array(eArray, 1);
  
  log_error = global_logging;
    
  //Generate/find keys
  if(!file_exists(full_file)|| !load_file(full_file))
    build_file(full_file);
}
//Constructor with file location
public_key_base::public_key_base(const string& fileloc)
{
  global_file_loc = fileloc;
  string full_file = fileloc+"/"+KEY_FILE_NAME;
  _username = _password = "";

  uint32_t eArray[1];
  eArray[0] = (1<<16)+1;
  e.push_array(eArray, 1);

  log_error = global_logging;
  
  //Generate/find keys
  if(!file_exists(full_file) || !load_file(full_file))
    build_file(full_file);
}
public_key_base::public_key_base(const string& username, const string& password)
{
  global_file_loc = ".";
  string full_file = "./";
  full_file = full_file+KEY_FILE_NAME;
  _username = username;
  _password = password;

  uint32_t eArray[1];
  eArray[0] = (1<<16)+1;
  e.push_array(eArray, 1);

  log_error = global_logging;
  
  //Generate/find keys
  if(!file_exists(full_file)|| !load_file(full_file))
    build_file(full_file);
}
public_key_base::public_key_base(const string& fileloc, const string& username, const string& password)
{
  global_file_loc = fileloc;
  string full_file = fileloc+"/"+KEY_FILE_NAME;
  _username = username;
  _password = password;
  
  uint32_t eArray[1];
  eArray[0] = (1<<16)+1;
  e.push_array(eArray, 1);

  log_error = global_logging;
  
  //Generate/find keys
  if(!file_exists(full_file) || !load_file(full_file))
    build_file(full_file);
}
//Destructor
public_key_base::~public_key_base()
{
}

//Building Public Keys-------------------------------------------------------

//Builds the file
bool public_key_base::build_file(const string& full_file)
{
  if(log_error)
      cryptoout<<"Generating public and private keys..."<<endl;
  large_integer p = generate_half_prime();
  large_integer q = generate_half_prime();
  
  //Generate n
  n = p*q;
  old_n = n;
  
  //Generate one
  uint32_t temp_array[1];
  temp_array[0] = 1;
  large_integer one(temp_array,1);
  
  //Generate phi
  large_integer phi = (p-one)*(q-one);

  d = e.mod_inverse(phi);
  old_d = d;
  if(log_error)
      cryptoout<<"Keys generated.  Saving keys."<<endl;
  
  return save_file(full_file);
}
//Saves the file
bool public_key_base::save_file(const string& full_file)
{
	ofstream output(full_file.c_str());
  
  //Check if the file build is good
  if(!output.good())
  {
    output.close();
    cryptoerr<<"Cannot construct the \""<<KEY_FILE_NAME<<"\" in the indicated directory"<<endl;
    cryptoerr<<"Aborting program!"<<endl;
    exit(EXIT_FAILURE);
    return false;
  }
  
  output<<"Timestamp:"<<get_timestamp()<<endl;
  output<<"Type:"<<0<<endl;

  //Generate output stream
  char* strm = NULL;
  RCFour* encry_stream = NULL;
  if(_username.length() != 0 && _password.length() != 0)
	  strm = new char[_username.length()+_password.length()];
  if(strm != NULL)
  {
	  int cnt = 0;
	  while(cnt<_username.length())
	  {
		  strm[cnt] = _username.c_str()[cnt];
		  cnt++;
	  }
	  while(cnt<_username.length()+_password.length())
	  {
		  strm[cnt] = _password.c_str()[cnt-_username.length()];
		  cnt++;
	  }
	  encry_stream = new RCFour((uint8_t*)strm,_username.length()+_password.length());
	  delete []  strm;
  }
	  

  int cnt = LARGE_NUMBER_SIZE/2-1;
  output<<"Public:";
  while(cnt>=0)
  {
	uint32_t temp = to_comp_mode_sgtw(n.getArrayNumber(cnt));

	if(encry_stream!=NULL)
	{
		((char*) &temp)[0] = ((char*) &temp)[0] ^ encry_stream->getNext();
		((char*) &temp)[1] = ((char*) &temp)[1] ^ encry_stream->getNext();
		((char*) &temp)[2] = ((char*) &temp)[2] ^ encry_stream->getNext();
		((char*) &temp)[3] = ((char*) &temp)[3] ^ encry_stream->getNext();
	}
	output<<temp;
    cnt--;
    if(cnt>=0)
      output<<"-";
  }
  output<<endl;
  
  cnt = LARGE_NUMBER_SIZE/2-1;
  output<<"Private:";
  while(cnt>=0)
  {
	uint32_t temp = to_comp_mode_sgtw(d.getArrayNumber(cnt));

	if(encry_stream!=NULL)
	{
		((char*) &temp)[0] = ((char*) &temp)[0] ^ encry_stream->getNext();
		((char*) &temp)[1] = ((char*) &temp)[1] ^ encry_stream->getNext();
		((char*) &temp)[2] = ((char*) &temp)[2] ^ encry_stream->getNext();
		((char*) &temp)[3] = ((char*) &temp)[3] ^ encry_stream->getNext();
	}
	output<<temp;
    cnt--;
    if(cnt>=0)
      output<<"-";
  }
  output<<endl;
  
  cnt = LARGE_NUMBER_SIZE/2-1;
  output<<"Old-Public:";
  while(cnt>=0)
  {
    uint32_t temp = to_comp_mode_sgtw(old_n.getArrayNumber(cnt));

	if(encry_stream!=NULL)
	{
		((char*) &temp)[0] = ((char*) &temp)[0] ^ encry_stream->getNext();
		((char*) &temp)[1] = ((char*) &temp)[1] ^ encry_stream->getNext();
		((char*) &temp)[2] = ((char*) &temp)[2] ^ encry_stream->getNext();
		((char*) &temp)[3] = ((char*) &temp)[3] ^ encry_stream->getNext();
	}
	output<<temp;
    cnt--;
    if(cnt>=0)
      output<<"-";
  }
  output<<endl;
  
  cnt = LARGE_NUMBER_SIZE/2-1;
  output<<"Old-Private:";
  while(cnt>=0)
  {
    uint32_t temp = to_comp_mode_sgtw(old_d.getArrayNumber(cnt));

	if(encry_stream!=NULL)
	{
		((char*) &temp)[0] = ((char*) &temp)[0] ^ encry_stream->getNext();
		((char*) &temp)[1] = ((char*) &temp)[1] ^ encry_stream->getNext();
		((char*) &temp)[2] = ((char*) &temp)[2] ^ encry_stream->getNext();
		((char*) &temp)[3] = ((char*) &temp)[3] ^ encry_stream->getNext();
	}
	output<<temp;
    cnt--;
    if(cnt>=0)
      output<<"-";
  }
  output<<endl;
  
  output.close();
  return true;
  if(encry_stream!=NULL)
	delete encry_stream;
}
//Loads the file
bool public_key_base::load_file(const string& full_file)
{
  ifstream input(full_file.c_str());
  
  //Ensure the file is good
  if(!input.good())
  {
    input.close();
    cryptoerr<<"Cannot load the \""<<KEY_FILE_NAME<<"\" in the indicated directory"<<endl;
    cryptoerr<<"Attempting to construct file instead"<<endl;
    return false;
  }
  
  //Read till a colon
  char temp = ' ';
  while(temp!=':'&&!input.eof())
    input>>temp;
  
  //Check for end of the file
  if(input.eof())
  {
    input.close();
    if(log_error)
    {
        cryptoerr<<"Error in loading the \""<<KEY_FILE_NAME<<"\""<<endl;
        cryptoerr<<"Attempting to construct file instead"<<endl;
    }
    return false;
  }
  input>>temp;
  
  //Read timestamp
  string stmp = "";
  while(check_numeric(temp)&&!input.eof())
  {
    stmp = stmp + temp;
    input>>temp;
  }
  
  //Check for end of the file
  if(input.eof())
  {
    input.close();
    if(log_error)
    {
        cryptoerr<<"Error in loading the \""<<KEY_FILE_NAME<<"\""<<endl;
        cryptoerr<<"Attempting to construct file instead"<<endl;
    }
    return false;
  }
  
  //Test timestamp
  if(convert_64(stmp)>get_timestamp())
  {
    input.close();
    if(log_error)
    {
        cryptoerr<<"Invalid timestamp"<<endl;
        cryptoerr<<"Constructing keys instead"<<endl;
    }
    return false;
  }
  
  //Read till a colon
  temp = ' ';
  while(temp!=':'&&!input.eof())
    input>>temp;
  
  //Check for end of the file
  if(input.eof())
  {
    input.close();
    if(log_error)
    {
          cryptoerr<<"Error in loading the \""<<KEY_FILE_NAME<<"\""<<endl;
          cryptoerr<<"Attempting to construct file instead"<<endl;
    }
    return false;
  }
  input>>temp;
  
  //Check for end of the file
  if(input.eof())
  {
    input.close();
    if(log_error)
    {
        cryptoerr<<"Error in loading the \""<<KEY_FILE_NAME<<"\""<<endl;
        cryptoerr<<"Attempting to construct file instead"<<endl;
    }
    return false;
  }
  
  //Generate output stream
  char* strm = NULL;
  RCFour* encry_stream = NULL;
  if(_username.length() != 0 && _password.length() != 0)
	  strm = new char[_username.length()+_password.length()];
  if(strm != NULL)
  {
	  int cnt = 0;
	  while(cnt<_username.length())
	  {
		  strm[cnt] = _username.c_str()[cnt];
		  cnt++;
	  }
	  while(cnt<_username.length()+_password.length())
	  {
		  strm[cnt] = _password.c_str()[cnt-_username.length()];
		  cnt++;
	  }
	  encry_stream = new RCFour((uint8_t*)strm,_username.length()+_password.length());
	  delete []  strm;
  }

  //Check index
  if(temp=='0')
  {
    //Index 0
    uint32_t readArray[LARGE_NUMBER_SIZE];
    int cnt = LARGE_NUMBER_SIZE/2-1;
    
    //Read public key
    
    //Read till a colon
    temp = ' ';
    while(temp!=':'&&!input.eof())
      input>>temp;
    
    //Check for end of the file
    if(input.eof())
    {
      input.close();
      if(log_error)
      {
          cryptoerr<<"Error in loading the \""<<KEY_FILE_NAME<<"\""<<endl;
          cryptoerr<<"Attempting to construct file instead"<<endl;
      }
      return false;
    }
    input>>temp;
    
    while(cnt>=0)
    {
      //Ensure proper file layout
      if(!check_numeric(temp)||input.eof())
      {
		input.close();
        if(log_error)
        {
            cryptoerr<<"Error in loading the \""<<KEY_FILE_NAME<<"\""<<endl;
            cryptoerr<<"Attempting to construct file instead"<<endl;
        }
		if(encry_stream!=NULL)
			delete encry_stream;
		return false;
      }
      
      //Read till not an int
      stmp = "";
      while(check_numeric(temp)&&!input.eof())
      {
		stmp = stmp+temp;
		input>>temp;
      }
      input>>temp;
      uint32_t temp_num = (uint32_t) convert_64(stmp);
	  if(encry_stream!=NULL)
	  {
		((char*) &temp_num)[0] = ((char*) &temp_num)[0] ^ encry_stream->getNext();
		((char*) &temp_num)[1] = ((char*) &temp_num)[1] ^ encry_stream->getNext();
		((char*) &temp_num)[2] = ((char*) &temp_num)[2] ^ encry_stream->getNext();
		((char*) &temp_num)[3] = ((char*) &temp_num)[3] ^ encry_stream->getNext();
	  }
	  temp_num = from_comp_mode_sgtw(temp_num);

	  readArray[cnt] = temp_num;
      cnt--;
    }
    //Place public keys
    n.push_array(readArray,LARGE_NUMBER_SIZE/2);
    
    cnt = LARGE_NUMBER_SIZE/2-1;
    
    //Read private key
    //Read till a colon
    temp = ' ';
    while(temp!=':'&&!input.eof())
      input>>temp;
    
    //Check for end of the file
    if(input.eof())
    {
      input.close();
      if(log_error)
      {
          cryptoerr<<"Error in loading the \""<<KEY_FILE_NAME<<"\""<<endl;
          cryptoerr<<"Attempting to construct file instead"<<endl;
      }
	  if(encry_stream!=NULL)
			delete encry_stream;
      return false;
    }
    input>>temp;
    
    while(cnt>=0)
    {
      //Ensure proper file layout
      if(!check_numeric(temp)||input.eof())
      {
		input.close();
        if(log_error)
        {
            cryptoerr<<"Error in loading the \""<<KEY_FILE_NAME<<"\""<<endl;
              cryptoerr<<"Attempting to construct file instead"<<endl;
        }
		if(encry_stream!=NULL)
			delete encry_stream;
		return false;
      }
      
      //Read till not an int
      stmp = "";
      while(check_numeric(temp)&&!input.eof())
      {
		stmp = stmp+temp;
		input>>temp;
      }
      input>>temp;
      uint32_t temp_num = (uint32_t) convert_64(stmp);
	  if(encry_stream!=NULL)
	  {
		((char*) &temp_num)[0] = ((char*) &temp_num)[0] ^ encry_stream->getNext();
		((char*) &temp_num)[1] = ((char*) &temp_num)[1] ^ encry_stream->getNext();
		((char*) &temp_num)[2] = ((char*) &temp_num)[2] ^ encry_stream->getNext();
		((char*) &temp_num)[3] = ((char*) &temp_num)[3] ^ encry_stream->getNext();
	  }
	  temp_num = from_comp_mode_sgtw(temp_num);

	  readArray[cnt] = temp_num;
      cnt--;
    }
    //Place private keys
    d.push_array(readArray,LARGE_NUMBER_SIZE/2);
    cnt = LARGE_NUMBER_SIZE/2-1;
    
    //Read old private key
    //Read till a colon
    temp = ' ';
    while(temp!=':'&&!input.eof())
      input>>temp;
    
    //Check for end of the file
    if(input.eof())
    {
      input.close();
      if(log_error)
      {
            cryptoerr<<"Error in loading the \""<<KEY_FILE_NAME<<"\""<<endl;
            cryptoerr<<"Attempting to construct file instead"<<endl;
      }
	  if(encry_stream!=NULL)
			delete encry_stream;
      return false;
    }
    input>>temp;
    
    while(cnt>=0)
    {
      //Ensure proper file layout
      if(!check_numeric(temp)||input.eof())
      {
		input.close();
        if(log_error)
        {
            cryptoerr<<"Error in loading the \""<<KEY_FILE_NAME<<"\""<<endl;
            cryptoerr<<"Attempting to construct file instead"<<endl;
        }
        if(encry_stream!=NULL)
			delete encry_stream;
		return false;
      }
      
      //Read till not an int
      stmp = "";
      while(check_numeric(temp)&&!input.eof())
      {
		stmp = stmp+temp;
		input>>temp;
      }
      input>>temp;
      uint32_t temp_num = (uint32_t) convert_64(stmp);
	  if(encry_stream!=NULL)
	  {
		((char*) &temp_num)[0] = ((char*) &temp_num)[0] ^ encry_stream->getNext();
		((char*) &temp_num)[1] = ((char*) &temp_num)[1] ^ encry_stream->getNext();
		((char*) &temp_num)[2] = ((char*) &temp_num)[2] ^ encry_stream->getNext();
		((char*) &temp_num)[3] = ((char*) &temp_num)[3] ^ encry_stream->getNext();
	  }
	  temp_num = from_comp_mode_sgtw(temp_num);

	  readArray[cnt] = temp_num;
      cnt--;
    }
    //Place old public keys
    old_n.push_array(readArray,LARGE_NUMBER_SIZE/2);
    
    //Read old private key
    //Read till a colon
    temp = ' ';
    cnt = LARGE_NUMBER_SIZE/2-1;
    
    while(temp!=':'&&!input.eof())
      input>>temp;
    
    //Check for end of the file
    if(input.eof())
    {
      input.close();
      if(log_error)
      {
          cryptoerr<<"Error in loading the \""<<KEY_FILE_NAME<<"\""<<endl;
          cryptoerr<<"Attempting to construct file instead"<<endl;
      }
	  if(encry_stream!=NULL)
			delete encry_stream;
      return false;
    }
    input>>temp;
    
    while(cnt>=0)
    {
      //Ensure proper file layout
      if(!check_numeric(temp)||input.eof())
      {
		input.close();
        if(log_error)
        {
            cryptoerr<<"Error in loading the \""<<KEY_FILE_NAME<<"\""<<endl;
            cryptoerr<<"Attempting to construct file instead"<<endl;
        }
		if(encry_stream!=NULL)
			delete encry_stream;
		return false;
      }
      
      //Read till not an int
      stmp = "";
      while(check_numeric(temp)&&!input.eof())
      {
		stmp = stmp+temp;
		input>>temp;
      }
      input>>temp;
      uint32_t temp_num = (uint32_t) convert_64(stmp);
	  if(encry_stream!=NULL)
	  {
		((char*) &temp_num)[0] = ((char*) &temp_num)[0] ^ encry_stream->getNext();
		((char*) &temp_num)[1] = ((char*) &temp_num)[1] ^ encry_stream->getNext();
		((char*) &temp_num)[2] = ((char*) &temp_num)[2] ^ encry_stream->getNext();
		((char*) &temp_num)[3] = ((char*) &temp_num)[3] ^ encry_stream->getNext();
	  }
	  temp_num = from_comp_mode_sgtw(temp_num);

	  readArray[cnt] = temp_num;
      cnt--;
    }
    //Place old private keys
    old_d.push_array(readArray,LARGE_NUMBER_SIZE/2);
    
    input.close();
	if(encry_stream!=NULL)
			delete encry_stream;
    return true;
  }
  
  input.close();
  if(encry_stream!=NULL)
			delete encry_stream;
  return false;
}
//Generates a prime with half the maximum bits
large_integer public_key_base::generate_half_prime() const
{
  srand(time(NULL));
  large_integer ret;
  uint32_t numArray[LARGE_NUMBER_SIZE/4];
  int cnt = 0;
  srand ( time(NULL) );
   while(cnt<(LARGE_NUMBER_SIZE/4))
   {
     numArray[cnt] = rand();
     cnt++;
   }
   numArray[0] = numArray[0] | 1;
   numArray[(LARGE_NUMBER_SIZE/4)-1] = numArray[(LARGE_NUMBER_SIZE/4)-1]|(1<<31);
   ret.push_array(numArray, (LARGE_NUMBER_SIZE/4));
   
   while(!ret.isPrime())
   {
     numArray[0]=numArray[0]+2;
     ret.push_array(numArray, (LARGE_NUMBER_SIZE/4));
   }
  
  return ret;
}
//Generates a new set of primes
bool public_key_base::generate_new_keys()
{
  //Copy n and d
  old_n = n;
  old_d = d;

  //Generate new keys
  ofstream output((global_file_loc+"/"+KEY_FILE_NAME).c_str());
  
  //Check if the file build is good
  if(!output.good())
  {
    output.close();
    cryptoerr<<"Cannot construct the \""<<KEY_FILE_NAME<<"\" in the indicated directory"<<endl;
    cryptoerr<<"Aborting program!"<<endl;
    exit(EXIT_FAILURE);
    return false;
  }

  output<<"Timestamp:"<<get_timestamp()<<endl;
  output<<"Type:"<<0<<endl;
  
  if(log_error)
      cryptoout<<"Generating public and private keys..."<<endl;
  large_integer p = generate_half_prime();
  large_integer q = generate_half_prime();
  
  //Generate n
  n = p*q;
  
  //Generate one
  uint32_t temp_array[1];
  temp_array[0] = 1;
  large_integer one(temp_array,1);
  
  //Generate phi
  large_integer phi = (p-one)*(q-one);

  d = e.mod_inverse(phi);
  
  int cnt = LARGE_NUMBER_SIZE/2-1;
  output<<"Public:";
  while(cnt>=0)
  {
    output<<n.getArrayNumber(cnt);
    cnt--;
    if(cnt>=0)
      output<<"-";
  }
  output<<endl;
  
  cnt = LARGE_NUMBER_SIZE/2-1;
  output<<"Private:";
  while(cnt>=0)
  {
    output<<d.getArrayNumber(cnt);
    cnt--;
    if(cnt>=0)
      output<<"-";
  }
  output<<endl;
  
  cnt = LARGE_NUMBER_SIZE/2-1;
  output<<"Old-Public:";
  while(cnt>=0)
  {
    output<<old_n.getArrayNumber(cnt);
    cnt--;
    if(cnt>=0)
      output<<"-";
  }
  output<<endl;
  
  cnt = LARGE_NUMBER_SIZE/2-1;
  output<<"Old-Private:";
  while(cnt>=0)
  {
    output<<old_d.getArrayNumber(cnt);
    cnt--;
    if(cnt>=0)
      output<<"-";
  }
  output<<endl;
  
  output.close();
  return true;
}

//large_integer Public Interface---------------------------------------------

//Returns the public n
large_integer public_key_base::get_n() const
{
  return n;
}
//Get old n
large_integer public_key_base::get_old_n() const
{
  return old_n;
}
bool public_key_base::change_password(const string& old_password, const string& new_password)
{
	if(old_password != _password)
		return false;
	_password = new_password;
	save_file(global_file_loc+"/"+KEY_FILE_NAME);
	return true;
}
//Returns the integer for the message size cap in bytes
int public_key_base::get_message_cap() const
{
  return (LARGE_NUMBER_SIZE*2);
}
//Encodes based on some public n
large_integer public_key_base::encode(const large_integer& code, const large_integer& pub_n) const
{
  if(code>n && log_error)
    cryptoerr<<"Warning: code is larger than public key (encode)"<<endl;
  return code.modExpo(e,pub_n);
}
//Encode a byte array
char* public_key_base::encode(char* code, const int code_len, const large_integer& pub_key) const
{
  //Test code length
  if(code_len>get_message_cap()&& log_error)
  {
    cryptoerr<<"Message length is larger than the cap"<<endl;
    cryptoerr<<"Message will be culled"<<endl;
  }

  //Build array
  char array[LARGE_NUMBER_SIZE*2];
  int cnt = 0;
  
  while(cnt<code_len&&cnt<get_message_cap())
  {
    array[cnt] = code[cnt];
    cnt++;
  }
  while(cnt<get_message_cap())
  {
    array[cnt] = 0;
    cnt++;
  }

  //Must perform compatibility swap
  cnt = 0;
  while(cnt<LARGE_NUMBER_SIZE/2)
  {
	  ((uint32_t*) array)[cnt] = to_comp_mode_sgtw(((uint32_t*) array)[cnt]);
	  cnt++;
  }
  
  //Convert to large integer
  large_integer hld((uint32_t*) array, get_message_cap()/4);
  hld = encode(hld,pub_key);
  uint32_t int_array[LARGE_NUMBER_SIZE*2];
  cnt = 0;
  while(cnt<(get_message_cap()/4))
  {
    int_array[cnt] = hld.getArrayNumber(cnt);
    cnt++;
  }
  
  //Convert back to char
  char* temp;
  temp = (char*)int_array;
  cnt = 0;
  while(cnt<get_message_cap())
  {
    code[cnt] = temp[cnt];
    cnt++;
  }
  
  return code;
}
//Encode a byte array
char* public_key_base::encode(char* code, const int code_len,const char* key, const int key_len) const
{
  //Test code length
  if(key_len>get_message_cap()&& log_error)
  {
    cryptoerr<<"Key length is larger than the cap"<<endl;
    cryptoerr<<"Key will be culled"<<endl;
  }
  //Build array
  char array[LARGE_NUMBER_SIZE*2];
  int cnt = 0;
  
  while(cnt<code_len&&cnt<get_message_cap())
  {
    array[cnt] = code[cnt];
    cnt++;
  }
  while(cnt<get_message_cap())
  {
    array[cnt] = 0;
    cnt++;
  }
  
  //Must perform compatibility swap
  cnt = 0;
  while(cnt<LARGE_NUMBER_SIZE/2)
  {
	  ((uint32_t*) array)[cnt] = to_comp_mode_sgtw(((uint32_t*) array)[cnt]);
	  cnt++;
  }

  //Convert to large integer
  large_integer pub_key((uint32_t*) array, get_message_cap()/4);
  
  return encode(code,code_len,pub_key);
}
//Decodes based on this private key
large_integer public_key_base::decode(const large_integer& code) const
{
  if(code>n&& log_error)
    cryptoerr<<"Warning: code is larger than public key (decode)"<<endl;
  return code.modExpo(d,n);
}
//Decodes a byte array
char* public_key_base::decode(char* code, const int code_len) const
{
  //Test code length
  if(code_len>get_message_cap()&& log_error)
  {
    cryptoerr<<"Message length is larger than the cap"<<endl;
    cryptoerr<<"Message will be culled"<<endl;
  }
  
  //Build array
  char array[LARGE_NUMBER_SIZE*2];
  int cnt = 0;
  
  while(cnt<code_len&&cnt<get_message_cap())
  {
    array[cnt] = code[cnt];
    cnt++;
  }
  while(cnt<get_message_cap())
  {
    array[cnt] = 0;
    cnt++;
  }

  //Must perform compatibility swap
  cnt = 0;
  while(cnt<LARGE_NUMBER_SIZE/2)
  {
	  ((uint32_t*) array)[cnt] = from_comp_mode_sgtw(((uint32_t*) array)[cnt]);
	  cnt++;
  }
  
  //Convert to large integer
  large_integer hld((uint32_t*) array, get_message_cap()/4);
  hld = decode(hld);
  uint32_t int_array[(LARGE_NUMBER_SIZE*2)/4];
  cnt = 0;
  while(cnt<(get_message_cap()/4))
  {
    int_array[cnt] = hld.getArrayNumber(cnt);
    cnt++;
  }
  
  //Convert back to char
  char* temp;
  temp = (char*)int_array;
  cnt = 0;
  while(cnt<get_message_cap())
  {
    code[cnt] = temp[cnt];
    cnt++;
  }
  
  return code;
}
//Decodes based on this private key
large_integer public_key_base::old_decode(const large_integer& code) const
{
  if(code>n&& log_error)
    cryptoerr<<"Warning: code is larger than public key (old decode)"<<endl;
  return code.modExpo(old_d,old_n);
}
//Decodes a byte array
char* public_key_base::old_decode(char* code, const int code_len) const
{
  //Test code length
  if(code_len>get_message_cap()&& log_error)
  {
    cryptoerr<<"Message length is larger than the cap"<<endl;
    cryptoerr<<"Message will be culled"<<endl;
  }
  
  //Build array
  char array[LARGE_NUMBER_SIZE*2];
  int cnt = 0;
  
  while(cnt<code_len&&cnt<get_message_cap())
  {
    array[cnt] = code[cnt];
    cnt++;
  }
  while(cnt<get_message_cap())
  {
    array[cnt] = 0;
    cnt++;
  }
  
  //Must perform compatibility swap
  cnt = 0;
  while(cnt<LARGE_NUMBER_SIZE/2)
  {
	  ((uint32_t*) array)[cnt] = from_comp_mode_sgtw(((uint32_t*) array)[cnt]);
	  cnt++;
  }

  //Convert to large integer
  large_integer hld((uint32_t*) array, get_message_cap()/4);
  hld = old_decode(hld);
  uint32_t int_array[(LARGE_NUMBER_SIZE*2)/4];
  cnt = 0;
  while(cnt<(get_message_cap()/4))
  {
    int_array[cnt] = hld.getArrayNumber(cnt);
    cnt++;
  }
  
  //Convert back to char
  char* temp;
  temp = (char*)int_array;
  cnt = 0;
  while(cnt<get_message_cap())
  {
    code[cnt] = temp[cnt];
    cnt++;
  }
  
  return code;
}

#endif

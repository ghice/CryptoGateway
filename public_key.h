//Primary author: Jonathan Bedard
//Certified working 9/2/14

#ifndef PUBLIC_KEY_H
#define PUBLIC_KEY_H

#include <string>
#include <stdint.h>
#include "large_number.h"

#define KEY_FILE_NAME "private_RSA_key.rcf"

using namespace std;

class public_key_base
{
private:
  large_integer n;
  large_integer d;
  
  large_integer old_n;
  large_integer old_d;
  string global_file_loc;
  
  large_integer e;
  
  bool build_file(const string& full_file);
  bool load_file(const string& full_file);
public:
  public_key_base();
  public_key_base(const string& fileloc);
  virtual ~public_key_base();
  
  large_integer generate_half_prime() const;
  bool generate_new_keys();
  
  large_integer get_n() const;
  large_integer get_old_n() const;
  
  int get_message_cap() const;
  large_integer encode(const large_integer& code, const large_integer& pub_n) const;
  char* encode(char* code, const int code_len,
			const large_integer& pub_key) const;
  char* encode(char* code, const int code_len,
			const char* key, const int key_len) const;
  large_integer decode(const large_integer& code) const;
  char* decode(char* code, const int code_len) const;
  large_integer old_decode(const large_integer& code) const;
  char* old_decode(char* code, const int code_len) const;
};

#endif

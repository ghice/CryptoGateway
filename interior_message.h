//Primary author: Jonathan Bedard
//Certified working 10/28/2014

#ifndef INTERIOR_MESSAGE_H
#define INTERIOR_MESSAGE_H

#include <stdint.h>
#include <cstdlib>
#include <iostream>

#define MESSAGE_MAX 512

using namespace std;

class interior_message
{
private:
  uint8_t message_data[MESSAGE_MAX];
  int length;
  
public:
  interior_message();
  interior_message(char* data, int len);
  interior_message(uint8_t* data, int len);
  
  interior_message(const interior_message& source);
  const interior_message& operator=(const interior_message& equ);

  friend ostream& operator<<(ostream& os, const interior_message& obj);
  
  void push_data(char* data, int len);
  void push_data(uint8_t* data, int len);
  void push_length(int len);
  
  int get_length() const;
  int get_full_length() const;
  
  char* get_char_data();
  uint8_t* get_int_data();
};

#endif
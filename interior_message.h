//Primary author: Jonathan Bedard
//Certified working 10/6/2015

#ifndef INTERIOR_MESSAGE_H
#define INTERIOR_MESSAGE_H
   
#include <memory>
#include <stdint.h>
#include <cstdlib>
#include <iostream>

namespace crypto {
    
const unsigned int MESSAGE_MAX=512;
const unsigned int CHECKSUM_SIZE=4;
extern bool global_logging;

class checksum_message;
class interior_message
{
protected:
  uint8_t message_data[MESSAGE_MAX];
  int length;
  
public:
  interior_message();
  interior_message(char* data, int len);
  interior_message(uint8_t* data, int len);
    //virtual ~interior_message() { std::cout<<"msg delete: "<<std::hex<<this<<std::endl; }
  
  interior_message(const interior_message& source);
  const interior_message& operator=(const interior_message& equ);

  friend std::ostream& operator<<(std::ostream& os, const interior_message& obj)
  {
    int cnt = 0;
    while(cnt<obj.length)
    {
        os<<(uint32_t) obj.message_data[cnt];
        cnt++;
        if(cnt<obj.length)
            os<<':';
    }
    return os;
  }
  
  void virtual push_data(char* data, int len);
  void virtual push_data(uint8_t* data, int len);
  void virtual push_length(int len);
    
  int virtual get_data_end();
  int get_length() const;
  int virtual get_full_length() const;
  
  char* get_char_data();
  uint8_t* get_int_data();
    
  bool push_string(std::string s);
  std::string pop_string();
};

class checksum_message:
    public interior_message
{
public:
    checksum_message();
    checksum_message(char* data, int len);
    checksum_message(uint8_t* data, int len);
    checksum_message(const interior_message& source);
    
    int virtual get_data_end();
    void virtual push_length(int len);
    int virtual get_full_length() const;
    
    uint32_t generate_checksum();
    uint32_t get_checksum();
    void bind_checksum();
    bool check_checksum();
};

typedef std::shared_ptr<interior_message> smartInteriorMessage;

}

#endif
//Primary author: Jonathan Bedard
//Confirmed working: 8/21/2015

//For testing purposes only

#ifndef END_TO_END_TEST_CPP
#define END_TO_END_TEST_CPP

#include <string>
#include <iostream>
#include <stdlib.h>

#include "cryptoLogging.h"
#include "public_key.h"
#include "security_gateway.h"

using namespace std;
using namespace crypto;

#ifndef MAIN
#define MAIN

int main()
{
  //Seed the random
  srand(time(NULL));
  
  cryptoout<<endl<<"End to end test"<<endl<<endl;
  
  //Generate the key infrastructure
  public_key_base pubKey(".");
  //pubKey.generate_new_keys();
  public_key_base pubKeyII("./KeyII");
  //pubKeyII.generate_new_keys();
  security_gateway new_gate;
  security_gateway gate_pair;
  
  new_gate.push_data(&pubKey,0,(char*)"ID_8362_Initial");
  gate_pair.push_data(&pubKeyII,0,(char*)"ID_234_Other_Pair");
  
  int cnt = 0;
  new_gate.push_old_key(pubKeyII.get_old_n());
  gate_pair.push_old_key(pubKey.get_old_n());
  
  //Testing security gateway
  
  //Establish connection
  smartInteriorMessage msg_test;
  
  cnt = 0;
  
  while(cnt<100)
  {
    msg_test= new_gate.get_message();
	cryptoout<<"Remote Processing"<<endl;

	int cnt2 = msg_test->get_length();
	while(cnt2<msg_test->get_full_length())
	{
		msg_test->get_int_data()[cnt2] = 0;
		cnt2++;
	}

    gate_pair.process_message(msg_test);
    cryptoout<<"Iteration: "<<cnt+1<<endl;
    if(new_gate.connected())
      cryptoout<<"\tNew gate is connected: ";
    else
      cryptoout<<"\tNew gate is not connected: ";
    cryptoout<<endl;
    
    msg_test = gate_pair.get_message();
	cryptoout<<"Base Processing"<<endl;

	cnt2 = msg_test->get_length();
	while(cnt2<msg_test->get_full_length())
	{
		msg_test->get_int_data()[cnt2] = 0;
		cnt2++;
	}

    new_gate.process_message(msg_test);
    if(gate_pair.connected())
      cryptoout<<"\tGate pair is connected: ";
    else
      cryptoout<<"\tGate pair is not connected: ";
    cryptoout<<endl;
    cnt++;
  }
 
  
  
  cryptoout<<endl<<"Completed test"<<endl<<endl;
  int finish;
  cin>>finish;
}
#endif

#endif

//Primary author: Jonathan Bedard
//Confirmed working: 10/6/2014

//For testing purposes only

#ifndef END_TO_END_TEST_CPP
#define END_TO_END_TEST_CPP

#include <string>
#include <iostream>
#include <stdlib.h>

#include "public_key.h"
#include "security_gateway.h"

using namespace std;

#ifndef MAIN
#define MAIN

int main()
{
  //Seed the random
  srand(time(NULL));
  
  cout<<endl<<"End to end test"<<endl<<endl;
  
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
  interior_message* msg_test;
  
  cnt = 0;
  
  while(cnt<100)
  {
    msg_test= new_gate.get_message();
	cout<<"Remote Processing"<<endl;

	int cnt2 = msg_test->get_length();
	while(cnt2<msg_test->get_full_length())
	{
		msg_test->get_int_data()[cnt2] = 0;
		cnt2++;
	}

    gate_pair.process_message(msg_test);
    cout<<"Iteration: "<<cnt+1<<endl;
    if(new_gate.connected())
      cout<<"\tNew gate is connected: ";
    else
      cout<<"\tNew gate is not connected: ";
    cout<<endl;
    
    msg_test = gate_pair.get_message();
	cout<<"Base Processing"<<endl;

	cnt2 = msg_test->get_length();
	while(cnt2<msg_test->get_full_length())
	{
		msg_test->get_int_data()[cnt2] = 0;
		cnt2++;
	}

    new_gate.process_message(msg_test);
    if(gate_pair.connected())
      cout<<"\tGate pair is connected: ";
    else
      cout<<"\tGate pair is not connected: ";
    cout<<endl;
    cnt++;
  }
 
  
  
  cout<<endl<<"Completed test"<<endl<<endl;
  int finish;
  cin>>finish;
}
#endif

#endif

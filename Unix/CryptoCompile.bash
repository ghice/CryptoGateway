#!/bin/bash

mkdir Debug

cd Debug
g++ -std=c++11 -c -w ../*.cpp -I ../../Datastructures

ar rvs CryptoGateway.a *.o
cd ..

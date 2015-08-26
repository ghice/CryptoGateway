#!/bin/bash

mkdir Debug

cd Debug
g++ -std=c++11 -c -w ../*.cpp

ar rvs CryptoGateway.a *.o
cd ..

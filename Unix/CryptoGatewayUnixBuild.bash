#!/bin/bash

/bin/sh CryptoUnixDeconstruct.bash
cd ..
cp -r Unix/CryptoCompile.bash CryptoCompile.bash

cp -r Unix/securitySpinLock.h securitySpinLock.h
cp -r Unix/securitySpinLock.cpp securitySpinLock.cpp

cd Unix

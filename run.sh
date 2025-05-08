#!/bin/bash

#ensure /bin exist
mkdir ./bin

#compile
g++ -std=c++11  -o ./bin/aes ./src/*.cpp ./main.cpp

#format
echo
echo "###########This is the program part(non-part program):"
echo

#run bin
./bin/aes

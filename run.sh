#!/bin/bash
g++ -std=c++11  -o ./bin/aes ./src/*.cpp ./main.cpp

# clear
echo
echo
echo "###########This is the program part:"
echo
./bin/aes

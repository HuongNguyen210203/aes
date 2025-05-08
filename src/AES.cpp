#include <stdexcept>
#include <array>

#include "../include/AES.h"
#include "../include/KeyExpansion.h"
#include "../include/Utils.h"

// Define the static member
constexpr AES::StateMatrix AES::COEF;
constexpr AES::StateMatrix AES::INVCOEF;

// Constructor
AES::AES(const std::vector<uint8_t>& key) : Nb(4) 
{
    size_t keyLen = key.size();
    if (keyLen == 16) 
    {
        keySize = KeySize::AES_128;
        Nk = 4;
        Nr = 10;

    } else if (keyLen == 24) 
    {
        keySize = KeySize::AES_192;
        Nk = 6;
        Nr = 12;
    } else if (keyLen == 32) 
    {
        keySize = KeySize::AES_256;
        Nk = 8;
        Nr = 14;
    } else 
    {
        throw std::invalid_argument("Invalid key size");
    }

    roundKeys = AESKeyExpander::expandKey(key, Nk, Nr);
}

//Done
void AES::addRoundKey(StateMatrix& state, int round)
{
    
    for (int col=0; col<4; col++)
    {
        int index = round * 4 + col;
        // printf("Index: %d\n", index);
        // printf("Hex: 0x%x\n", roundKeys[index]);

        for (int row=0; row<4; row++)
        {
            // printf("Hex before xor: 0x%x\n", (roundKeys[index] & (0xff << (8 * (3 - row)))) >> (8 * (3 - row)));
            state[row][col] ^= (roundKeys[index] & (0xff << (8 * (3 - row)))) >> (8 * (3 - row));
            // printf("Hex after xor: 0x%x\n", state[row][col]);
        }
    }
}

std::vector<uint8_t> AES::encryptBlock(const std::vector<uint8_t>& input)
{
    
    StateMatrix state = AESUtils::bytesToStateMatrix(input);

    addRoundKey(state, 0);

    
    for (int i=1; i<Nr; i++)
    {
        subBytes(state);
        shiftRows(state);
        mixColumns(state);
        addRoundKey(state, i);
    }
    subBytes(state);
    shiftRows(state);
    addRoundKey(state, Nr);
    AESUtils::printState(state);
    return AESUtils::stateMatrixToBytes(state);
}

//Done
void AES::subBytes(StateMatrix& state)
{
    for (auto& row : state)
        for (auto& elem: row) 
            elem =  AESUtils::subByte(elem);
}



//Done
void AES::shiftRows(StateMatrix& state)
{
   StateMatrix temp = state;
    //0 1 2 3
    //1 2 3 0
    //2 3 0 1
    //3 0 1 2

    for (int row=1; row<4; row++)
        for (int col=0; col<4; col++)
            state[row][col] = temp[row][(col + row) % 4];
}

//Done
void AES::mixColumns(StateMatrix& state)
{

    StateMatrix temp = state;

    for (int col=0; col<4; col++)
    {
        for (int row=0; row<4; row++)
        {
            state[row][col] = AESUtils::gmul(COEF[row][0], temp[0][col]);
            for (int i = 1; i<4; i++)
                state[row][col] ^= AESUtils::gmul(COEF[row][i], temp[i][col]); 
        }
    }
    
}

//Done
std::vector<uint8_t> AES::decryptBlock(const std::vector<uint8_t>& input)
{
    StateMatrix state = AESUtils::bytesToStateMatrix(input);
    // Initial round key addition (last round key)
    addRoundKey(state, Nr);
    
    // Nr-1 downto 1 rounds
    for (int round = Nr - 1; round >= 1; --round)
    {
        printf("Round: %d\n", 10 - round);
        AESUtils::printState(state);
        invSubBytes(state);   
        AESUtils::printState(state);
        invShiftRows(state);  
        addRoundKey(state, round);
        invMixColumns(state); 

    }
    
    // Final round (no InvMixColumns)
    invShiftRows(state);
    invSubBytes(state);
    addRoundKey(state, 0);

    AESUtils::printState(state);
    return AESUtils::stateMatrixToBytes(state);
}

//Done
void AES::invSubBytes(StateMatrix& state)
{
    for (auto& row : state)
        for (auto& elem: row) 
            elem =  AESUtils::invSubByte(elem);
}

//Done
void AES::invShiftRows(StateMatrix& state)
{
    StateMatrix temp = state;
    //0 1 2 3 : row 0
    //3 0 1 2 : row 1
    //2 3 0 1 : row 2
    //1 2 3 0 : row 3
    for (int row=1; row<4; row++)
    {
        for (int col=0; col<4; col++)
        {
            state[row][col] = temp[row][(col + (4 - row)) % 4];
        }
    }
}

//Done
void AES::invMixColumns(StateMatrix& state)
{
     StateMatrix temp = state;

    for (int col=0; col<4; col++)
    {
        for (int row=0; row<4; row++)
        {
            state[row][col] = AESUtils::gmul(INVCOEF[row][0], temp[0][col]);
            for (int i = 1; i<4; i++)
                state[row][col] ^= AESUtils::gmul(INVCOEF[row][i], temp[i][col]); 
        }
    }
}


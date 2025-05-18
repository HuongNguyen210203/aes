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

// //Done
void AES::addRoundKey(StateMatrix& state, int round)
{
    int base = round * 4;

    uint32_t w0 = roundKeys[base + 0];
    uint32_t w1 = roundKeys[base + 1];
    uint32_t w2 = roundKeys[base + 2];
    uint32_t w3 = roundKeys[base + 3];

    state[0][0] ^= (w0 >> 24) & 0xFF;
    state[1][0] ^= (w0 >> 16) & 0xFF;
    state[2][0] ^= (w0 >> 8)  & 0xFF;
    state[3][0] ^= (w0)       & 0xFF;

    state[0][1] ^= (w1 >> 24) & 0xFF;
    state[1][1] ^= (w1 >> 16) & 0xFF;
    state[2][1] ^= (w1 >> 8)  & 0xFF;
    state[3][1] ^= (w1)       & 0xFF;

    state[0][2] ^= (w2 >> 24) & 0xFF;
    state[1][2] ^= (w2 >> 16) & 0xFF;
    state[2][2] ^= (w2 >> 8)  & 0xFF;
    state[3][2] ^= (w2)       & 0xFF;

    state[0][3] ^= (w3 >> 24) & 0xFF;
    state[1][3] ^= (w3 >> 16) & 0xFF;
    state[2][3] ^= (w3 >> 8)  & 0xFF;
    state[3][3] ^= (w3)       & 0xFF;
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
    //0 1 2 3
    //1 2 3 0
    //2 3 0 1
    //3 0 1 2
    StateMatrix temp = state;

    // Row 1 (shift left by 1)
    state[1][0] = temp[1][1];
    state[1][1] = temp[1][2];
    state[1][2] = temp[1][3];
    state[1][3] = temp[1][0];

    // Row 2 (shift left by 2)
    state[2][0] = temp[2][2];
    state[2][1] = temp[2][3];
    state[2][2] = temp[2][0];
    state[2][3] = temp[2][1];

    // Row 3 (shift left by 3)
    state[3][0] = temp[3][3];
    state[3][1] = temp[3][0];
    state[3][2] = temp[3][1];
    state[3][3] = temp[3][2];
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
    //0 1 2 3 : row 0
    //3 0 1 2 : row 1
    //2 3 0 1 : row 2
    //1 2 3 0 : row 3
    StateMatrix temp = state;
    
    // Row 1 (shift right by 1)
    state[1][0] = temp[1][3];
    state[1][1] = temp[1][0];
    state[1][2] = temp[1][1];
    state[1][3] = temp[1][2];

    // Row 2 (shift right by 2)
    state[2][0] = temp[2][2];
    state[2][1] = temp[2][3];
    state[2][2] = temp[2][0];
    state[2][3] = temp[2][1];

    // Row 3 (shift right by 3)
    state[3][0] = temp[3][1];
    state[3][1] = temp[3][2];
    state[3][2] = temp[3][3];
    state[3][3] = temp[3][0];
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


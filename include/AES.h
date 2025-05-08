#ifndef AES128_H
#define AES128_H


#include <vector>
#include <array>
#include <cstdint>

#include "./KeyExpansion.h"
#include "./Utils.h"

class AES {
public:
    enum class KeySize {
        AES_128 = 16,
        AES_192 = 24,
        AES_256 = 32
    };

    using StateMatrix = AESUtils::StateMatrix;

    AES(const std::vector<uint8_t>& key); // Constructor

    std::vector<uint8_t> encryptBlock(const std::vector<uint8_t>& input);
    std::vector<uint8_t> decryptBlock(const std::vector<uint8_t>& input);

private:
    KeySize keySize;
    uint8_t Nb; // Number of columns (always 4 in AES)
    uint8_t Nk; // Key length in 32-bit words
    uint8_t Nr; // Number of rounds
    std::vector<uint32_t> roundKeys;
    std::vector<uint32_t> roundKeysEq;
    
    static constexpr StateMatrix COEF{{
        {0x02, 0x03, 0x01, 0x01},
        {0x01, 0x02, 0x03, 0x01},
        {0x01, 0x01, 0x02, 0x03},
        {0x03, 0x01, 0x01, 0x02}
    }};

    static constexpr StateMatrix INVCOEF {{
        {0x0e, 0x0b, 0x0d, 0x09},
        {0x09, 0x0e, 0x0b, 0x0d},
        {0x0d, 0x09, 0x0e, 0x0b},
        {0x0b, 0x0d, 0x09, 0x0e}
    }};

    
    void addRoundKey(StateMatrix& state, int round);
    void subBytes(StateMatrix& state);
    void shiftRows(StateMatrix& state);
    void mixColumns(StateMatrix& state);

    void invSubBytes(StateMatrix& state);
    void invShiftRows(StateMatrix& state);
    void invMixColumns(StateMatrix& state);

};

#endif // AES128_H

#ifndef UTILS
#define UTILS

#include <vector>
#include <array>

class AESUtils {
public:
    static constexpr size_t BLOCK_SIZE = 4; // AES block width in words (32-bit)
    using StateMatrix = std::array<std::array<uint8_t, BLOCK_SIZE>, BLOCK_SIZE>; // 4x4 matrix

    static StateMatrix bytesToStateMatrix(const std::vector<uint8_t>& input);
    static std::vector<uint8_t> stateMatrixToBytes(const StateMatrix& state);
    
    static uint8_t gmul(uint8_t a, uint8_t b);
    static uint8_t subByte(uint8_t byte);
    static uint8_t invSubByte(uint8_t byte);

    static void printState(const std::array<std::array<uint8_t, 4>, 4>& state);
    
};

#endif
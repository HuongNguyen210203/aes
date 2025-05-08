#include <iostream>
#include <vector>
#include <array>
#include <cstdint>

#include "../include/Utils.h"

namespace UtilsTest {

void testBytesToStateMatrixAndBack() {
    std::vector<uint8_t> input(16);
    for (int i = 0; i < 16; ++i) input[i] = i;

    AESUtils::StateMatrix matrix = AESUtils::bytesToStateMatrix(input);
    std::vector<uint8_t> output = AESUtils::stateMatrixToBytes(matrix);

    bool testPassed = (input == output);
    std::cout << "Test BytesToStateMatrixAndBack: " 
              << (testPassed ? "PASSED" : "FAILED") << std::endl;
}

void testGmul() {
    bool testPassed = true;

    if (AESUtils::gmul(0x57, 0x83) != 0xc1) testPassed = false;
    if (AESUtils::gmul(0x53, 0xca) != 0x01) testPassed = false;

    std::cout << "Test Gmul: " << (testPassed ? "PASSED" : "FAILED") << std::endl;
}

void testSubByteInverse() {
    bool testPassed = true;
    
    for (uint16_t i = 0; i <= 0xFF; ++i) {
        uint8_t byte = static_cast<uint8_t>(i);
        if (AESUtils::invSubByte(AESUtils::subByte(byte)) != byte) {
            testPassed = false;
            break;
        }
    }

    std::cout << "Test SubByteInverseRoundTrip: " 
              << (testPassed ? "PASSED" : "FAILED") << std::endl;
}

}

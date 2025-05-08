#include <iostream>
#include <ostream>
#include <iomanip>

#include "../include/KeyExpansion.h"
#include "../include/Utils.h"

// Rotates a word left by one byte
uint32_t AESKeyExpander::rotWord(uint32_t word) {
    return (word << 8) | (word >> 24);
}

// Substitutes each byte using the AES S-box
uint32_t AESKeyExpander::subWord(uint32_t word) {
    return (AESUtils::subByte(word >> 24) << 24) |
           (AESUtils::subByte((word >> 16) & 0xFF) << 16) |
           (AESUtils::subByte((word >> 8) & 0xFF) << 8) |
           (AESUtils::subByte(word & 0xFF));
}

// Returns round constant
uint32_t AESKeyExpander::rcon(uint8_t i) {
    uint8_t rc = 1;
    for (uint8_t j = 1; j < i; ++j)
        rc = AESUtils::gmul(rc, 0x02);
    return rc << 24;
}

// Main key expansion function
std::vector<uint32_t> AESKeyExpander::expandKey(const std::vector<uint8_t>& key, uint8_t Nk, uint8_t Nr) {
    const uint8_t Nb = 4;
    size_t totalWords = Nb * (Nr + 1);
    std::vector<uint32_t> w(totalWords);

    // Initial key words
    for (uint8_t i = 0; i < Nk; ++i) {
        w[i] = (key[4 * i] << 24) |
               (key[4 * i + 1] << 16) |
               (key[4 * i + 2] << 8) |
               (key[4 * i + 3]);
    }

    for (uint32_t i = Nk; i < totalWords; ++i) {
        uint32_t temp = w[i - 1];
        if (i % Nk == 0) {
            temp = subWord(rotWord(temp)) ^ rcon(i / Nk);
        } else if (Nk > 6 && (i % Nk) == 4) {
            temp = subWord(temp);
        }
        w[i] = w[i - Nk] ^ temp;
    }

    return w;
}


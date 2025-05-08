#ifndef KEYEXPANSION_H
#define KEYEXPANSION_H

#include <string>
#include <array>


// Handles AES key expansion logic
class AESKeyExpander {
public:
    static std::vector<uint32_t> expandKey(const std::vector<uint8_t>& key, uint8_t Nk, uint8_t Nr);

private:
    static uint32_t rotWord(uint32_t word);
    static uint32_t subWord(uint32_t word);
    static uint32_t rcon(uint8_t i);
};



#endif // KEYEXPANSION_H
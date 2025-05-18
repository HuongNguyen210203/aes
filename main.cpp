//
// Created by debian on 27/04/2025.
//
#include <iostream>
#include <iomanip>

#include "./include/AES.h"


void printHex(const std::vector<uint8_t>& data) {
    for (uint8_t byte : data) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
    }
    std::cout << std::dec << std::endl;
}

int main() {
    std::vector<uint8_t> key = {
        0x2b, 0x7e, 0x15, 0x16,
        0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88,
        0x09, 0xcf, 0x4f, 0x3c
    };

    std::vector<uint8_t> plaintext = {
        0x32, 0x43, 0xf6, 0xa8,
        0x88, 0x5a, 0x30, 0x8d,
        0x31, 0x31, 0x98, 0xa2,
        0xe0, 0x37, 0x07, 0x34
    };

    std::vector<uint8_t> expectedCiphertext = {
        0x39, 0x25, 0x84, 0x1d,
        0x02, 0xdc, 0x09, 0xfb,
        0xdc, 0x11, 0x85, 0x97,
        0x19, 0x6a, 0x0b, 0x32
    };

    AES aes(key);

    std::vector<uint8_t> ciphertext = aes.encryptBlock(plaintext);
    std::vector<uint8_t> decrypted = aes.decryptBlock(ciphertext);

    std::cout << "Plaintext:          "; printHex(plaintext);
    std::cout << "Actual Ciphertext:  "; printHex(ciphertext);
    std::cout << "Expected Ciphertext:"; printHex(expectedCiphertext);
    std::cout << "Decrypted Text:     "; printHex(decrypted);

    return 0;
}

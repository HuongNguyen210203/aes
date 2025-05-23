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

void testAES128() {
    std::cout << "=== AES-128 Test ===" << std::endl;
    std::vector<uint8_t> key128 = {
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

    std::vector<uint8_t> expectedCiphertext128 = {
        0x39, 0x25, 0x84, 0x1d,
        0x02, 0xdc, 0x09, 0xfb,
        0xdc, 0x11, 0x85, 0x97,
        0x19, 0x6a, 0x0b, 0x32
    };

    AES aes128(key128);
    std::vector<uint8_t> ciphertext128 = aes128.encryptBlock(plaintext);
    std::vector<uint8_t> decrypted128 = aes128.decryptBlock(ciphertext128);

    std::cout << "Key:               "; printHex(key128);
    std::cout << "Plaintext:         "; printHex(plaintext);
    std::cout << "Actual Ciphertext: "; printHex(ciphertext128);
    std::cout << "Expected Ciphertext:"; printHex(expectedCiphertext128);
    std::cout << "Decrypted Text:    "; printHex(decrypted128);
    std::cout << std::endl;
}

void testAES192() {
    std::cout << "=== AES-192 Test ===" << std::endl;
    std::vector<uint8_t> key192 = {
        0x8e, 0x73, 0xb0, 0xf7,
        0xda, 0x0e, 0x64, 0x52,
        0xc8, 0x10, 0xf3, 0x2b,
        0x80, 0x90, 0x79, 0xe5,
        0x62, 0xf8, 0xea, 0xd2,
        0x52, 0x2c, 0x6b, 0x7b
    };

    std::vector<uint8_t> plaintext = {
        0x32, 0x43, 0xf6, 0xa8,
        0x88, 0x5a, 0x30, 0x8d,
        0x31, 0x31, 0x98, 0xa2,
        0xe0, 0x37, 0x07, 0x34
    };

    std::vector<uint8_t> expectedCiphertext192 = {
        0x1a, 0x93, 0x61, 0x7d,
        0x3c, 0x87, 0x5d, 0x2d,
        0x3e, 0x46, 0x7e, 0xb2,
        0x77, 0x6b, 0xa4, 0x24
    };

    AES aes192(key192);
    std::vector<uint8_t> ciphertext192 = aes192.encryptBlock(plaintext);
    std::vector<uint8_t> decrypted192 = aes192.decryptBlock(ciphertext192);

    std::cout << "Key:               "; printHex(key192);
    std::cout << "Plaintext:         "; printHex(plaintext);
    std::cout << "Actual Ciphertext: "; printHex(ciphertext192);
    std::cout << "Expected Ciphertext:"; printHex(expectedCiphertext192);
    std::cout << "Decrypted Text:    "; printHex(decrypted192);
    std::cout << std::endl;
}

void testAES256() {
    std::cout << "=== AES-256 Test ===" << std::endl;
    std::vector<uint8_t> key256 = {
        0x60, 0x3d, 0xeb, 0x10,
        0x15, 0xca, 0x71, 0xbe,
        0x2b, 0x73, 0xae, 0xf0,
        0x85, 0x7d, 0x77, 0x81,
        0x1f, 0x35, 0x2c, 0x07,
        0x3b, 0x61, 0x08, 0xd7,
        0x2d, 0x98, 0x10, 0xa3,
        0x09, 0x14, 0xdf, 0xf4
    };

    std::vector<uint8_t> plaintext = {
        0x32, 0x43, 0xf6, 0xa8,
        0x88, 0x5a, 0x30, 0x8d,
        0x31, 0x31, 0x98, 0xa2,
        0xe0, 0x37, 0x07, 0x34
    };

    std::vector<uint8_t> expectedCiphertext256 = {
        0x52, 0x09, 0x6a, 0xd5,
        0x30, 0x36, 0xa5, 0x38,
        0xbf, 0x40, 0xa3, 0x9e,
        0x81, 0xf3, 0xd7, 0xfb
    };

    AES aes256(key256);
    std::vector<uint8_t> ciphertext256 = aes256.encryptBlock(plaintext);
    std::vector<uint8_t> decrypted256 = aes256.decryptBlock(ciphertext256);

    std::cout << "Key:               "; printHex(key256);
    std::cout << "Plaintext:         "; printHex(plaintext);
    std::cout << "Actual Ciphertext: "; printHex(ciphertext256);
    std::cout << "Expected Ciphertext:"; printHex(expectedCiphertext256);
    std::cout << "Decrypted Text:    "; printHex(decrypted256);
}

int main() {
    testAES128();
    testAES192();
    testAES256();
    return 0;
}

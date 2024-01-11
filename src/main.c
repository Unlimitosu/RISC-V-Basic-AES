#include <stdio.h>
#include <stdint.h>

#define nr 10


extern void SubBytes(uint8_t* state);
extern void ShiftRows(uint8_t* state);
extern void MixColumn(uint8_t* state);
extern void AddRoundKey(uint8_t* state, uint32_t* rk);

uint32_t rk[] = {
    0x0f1571c9, 0x47d9e859, 0x0cb7add6, 0xaf7f6798,
    0xdc9037b0, 0x9b49dfe9, 0x97fe723f, 0x388115a7,
    0xd2c96bb7, 0x4980b45e, 0xde7ec661, 0xe6ffd3c6,
    0xc0afdf39, 0x892f6b67, 0x5751ad06, 0xb1ae7ec0,
    0x2c5c65f1, 0xa5730e96, 0xf222a390, 0x438cdd50,
    0x589d36eb, 0xfdee387d, 0x0fcc9bed, 0x4c4046bd,
    0x71c74cc2, 0x8c2974bf, 0x83e5ef52, 0xcfa5a9ef,
    0x37149348, 0xbb3de7f7, 0x38d808a5, 0xf77da14a,
    0x48264520, 0xf31ba2d7, 0xcbc3aa72, 0x3cbe0b38,
    0xfd0d42cb, 0x0e16e01c, 0xc5d54a6e, 0xf96b4156,
    0xb48ef352, 0xba98134e, 0x7f4d5920, 0x86261876 };

int main() {
    uint8_t pt[16] = {0,};

    for(int i = 0; i < 16; i++){
        pt[i] = i;
    }

    AddRoundKey(pt, rk);
    for(int r = 1; r < nr; r++){
        SubBytes(pt);
        ShiftRows(pt);
        MixColumn(pt);
        AddRoundKey(pt, rk);
    }
    SubBytes(pt);
    ShiftRows(pt);
    AddRoundKey(pt, rk);

    printf("mine\n");
    for(int i = 0; i < 16; i++){
        printf("%02x ", pt[i]);
    }printf("\n");

    
    return 0;
}
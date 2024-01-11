#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#define ENCRYPT 980815
#define DECRYPT 941010

#define MODE_ECB 0X01010
#define MODE_CBC 0X01FFF
#define MODE_CTR 0X0ABCD

#define GF_Add(a, b) ((a) ^ (b)) // GF 에서의 덧셈

const uint32_t RC[11] = { 0x00000000, 0x01000000, 0x02000000, 0x04000000, 0x08000000, 0x10000000, 0x20000000, 0x40000000, 0x80000000, 0x1b000000, 0x36000000 };
const uint8_t AC[8] = { 0xf1, 0xe3, 0xc7, 0x8f, 0x1f, 0x3e, 0x7c, 0xf8 }; // Affine 변환을 위한 8x8 행렬의 행을 16진수로 저장
const uint8_t Inv_S_box[256] = {
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
};
const uint8_t POT[8] = { 1, 2, 4, 8, 16, 32, 64, 128 }; // 2^0 부터 2^7 배열


void byteToInt(uint8_t *bit, uint32_t *integer)
{
    integer[0] = (bit[0] << 24) ^ (bit[1] << 16) ^ (bit[2] << 8) ^ bit[3];
    integer[1] = (bit[4] << 24) ^ (bit[5] << 16) ^ (bit[6] << 8) ^ bit[7];
    integer[2] = (bit[8] << 24) ^ (bit[9] << 16) ^ (bit[10] << 8) ^ bit[11];
    integer[3] = (bit[12] << 24) ^ (bit[13] << 16) ^ (bit[14] << 8) ^ bit[15];
}

void intToByte(uint32_t* integer, uint8_t* bit) // 32-bit 정수 배열을 8-bit 정수 배열로 변환 
{
    for(int cnt_i = 0; cnt_i < 4; cnt_i++) {
        bit[cnt_i * 4 + 0] = integer[cnt_i] >> 24;
        bit[cnt_i * 4 + 1] = integer[cnt_i] >> 16;
        bit[cnt_i * 4 + 2] = integer[cnt_i] >> 8;
        bit[cnt_i * 4 + 3] = integer[cnt_i];
    }
}

uint8_t xtimes_DH(uint8_t f) {
    return (((f) << 1) ^ (((f) >> 7) * 0x1b));
}

uint8_t GF_Mul(uint8_t f, uint8_t g) // GF(2^8) 에서의 곱셈
{
    uint8_t result = 0x00;
    int coef;

    for(int cnt_i = 7; cnt_i >= 0; cnt_i--)
    {
        coef = (f >> cnt_i) & 0x01;

        result = xtimes_DH(result);

        if(coef == 1) {
            result = GF_Add(result, g);
        }
    }

    return result;
}

uint8_t GF_Inv(uint8_t x) // GF(2^8) 에서의 역원
{
    uint8_t x_inv, term;
    x_inv = 1;
    term = x;

    if(x == 0) return 0;

    for(int cnt_i = 0; cnt_i < 7; cnt_i++)
    {
        term = GF_Mul(term, term);
        x_inv = GF_Mul(x_inv, term);
    }

    return x_inv;
}

uint8_t S_Box(uint8_t x) // y = f(x) : input x , output y
{
    uint8_t x_Inv = GF_Inv(x);
    uint8_t y = 0x00, temp = 0x00, cnt = 0x00;

    for(int cnt_i = 0; cnt_i < 8; cnt_i++)
    {
        cnt = 0;
        temp = AC[cnt_i] & x_Inv;

        for(int cnt_j = 0; cnt_j < 8; cnt_j++) // 각 자리 수 더하기
        {
            cnt += (temp >> cnt_j) & 0x01;
        }

        if(cnt & 0x01) { // 더한 값이 홀수면 1, 짝수면 0 (첫번째 비트가 1이면 홀수, 0이면 짝수)
            y += POT[cnt_i]; 
        }
    }

    y = y ^ 0x63; // GF(2^8) 덧셈 ( + [ 0 1 1 0 0 0 1 1 ])

    return y;
}

void SubBytes(uint8_t* state) { // 1 byte x 16 입출력
    for(int cnt_i = 0; cnt_i < 16; cnt_i++)
    {
        state[cnt_i] = S_Box(state[cnt_i]);
    }
}

void ShiftRows(uint8_t* state) { // 1 byte x 16 입출력 
    uint8_t temp;

    temp = state[4];
    state[4] = state[5];
    state[5] = state[6];
    state[6] = state[7];
    state[7] = temp;

    temp = state[8];
    state[8] = state[10];
    state[10] = temp;
    temp = state[9];
    state[9] = state[11];
    state[11] = temp;

    temp = state[15];
    state[15] = state[14];
    state[14] = state[13];
    state[13] = state[12];
    state[12] = temp;
}

void Inv_ShiftRows(uint8_t* state)
{
    uint8_t temp;

    temp = state[7];
    state[7] = state[6];
    state[6] = state[5];
    state[5] = state[4];
    state[4] = temp;

    temp = state[8];
    state[8] = state[10];
    state[10] = temp;
    temp = state[9];
    state[9] = state[11];
    state[11] = temp;

    temp = state[12];
    state[12] = state[13];
    state[13] = state[14];
    state[14] = state[15];
    state[15] = temp;
}

void MixColumn(uint8_t* state){ // 1 byte x 16 입출력
    uint8_t result[16] = { 0x00, };

    result[0] = xtimes_DH(state[0])^(xtimes_DH(state[4])^state[4])^state[8]^state[12];
    result[1] = xtimes_DH(state[1])^(xtimes_DH(state[5])^state[5])^state[9]^state[13];
    result[2] = xtimes_DH(state[2])^(xtimes_DH(state[6])^state[6])^state[10]^state[14];
    result[3] = xtimes_DH(state[3])^(xtimes_DH(state[7])^state[7])^state[11]^state[15];

    result[4] = state[0]^xtimes_DH(state[4])^(xtimes_DH(state[8])^state[8])^state[12];
    result[5] = state[1]^xtimes_DH(state[5])^(xtimes_DH(state[9])^state[9])^state[13];
    result[6] = state[2]^xtimes_DH(state[6])^(xtimes_DH(state[10])^state[10])^state[14];
    result[7] = state[3]^xtimes_DH(state[7])^(xtimes_DH(state[11])^state[11])^state[15];

    result[8] = state[0]^state[4]^xtimes_DH(state[8])^(xtimes_DH(state[12])^state[12]);
    result[9] = state[1]^state[5]^xtimes_DH(state[9])^(xtimes_DH(state[13])^state[13]);
    result[10] = state[2]^state[6]^xtimes_DH(state[10])^(xtimes_DH(state[14])^state[14]);
    result[11] = state[3]^state[7]^xtimes_DH(state[11])^(xtimes_DH(state[15])^state[15]);

    result[12] = (xtimes_DH(state[0])^state[0])^state[4]^state[8]^xtimes_DH(state[12]);
    result[13] = (xtimes_DH(state[1])^state[1])^state[5]^state[9]^xtimes_DH(state[13]);
    result[14] = (xtimes_DH(state[2])^state[2])^state[6]^state[10]^xtimes_DH(state[14]);
    result[15] = (xtimes_DH(state[3])^state[3])^state[7]^state[11]^xtimes_DH(state[15]);

    for(int cnt_i = 0; cnt_i < 16; cnt_i++)
    {
        state[cnt_i] = result[cnt_i];
    }
}

void Inv_MixColumn(uint8_t* state) {
    uint8_t result[16] = { 0x00, };

    result[0] = (xtimes_DH(xtimes_DH(xtimes_DH(state[0])))^xtimes_DH(xtimes_DH(state[0]))^xtimes_DH(state[0]))^(xtimes_DH(xtimes_DH(xtimes_DH(state[4])))^xtimes_DH(state[4])^state[4])^(xtimes_DH(xtimes_DH(xtimes_DH(state[8])))^xtimes_DH(xtimes_DH(state[8]))^state[8])^(xtimes_DH(xtimes_DH(xtimes_DH(state[12])))^state[12]);
    result[1] = (xtimes_DH(xtimes_DH(xtimes_DH(state[1])))^xtimes_DH(xtimes_DH(state[1]))^xtimes_DH(state[1]))^(xtimes_DH(xtimes_DH(xtimes_DH(state[5])))^xtimes_DH(state[5])^state[5])^(xtimes_DH(xtimes_DH(xtimes_DH(state[9])))^xtimes_DH(xtimes_DH(state[9]))^state[9])^(xtimes_DH(xtimes_DH(xtimes_DH(state[13])))^state[13]);
    result[2] = (xtimes_DH(xtimes_DH(xtimes_DH(state[2])))^xtimes_DH(xtimes_DH(state[2]))^xtimes_DH(state[2]))^(xtimes_DH(xtimes_DH(xtimes_DH(state[6])))^xtimes_DH(state[6])^state[6])^(xtimes_DH(xtimes_DH(xtimes_DH(state[10])))^xtimes_DH(xtimes_DH(state[10]))^state[10])^(xtimes_DH(xtimes_DH(xtimes_DH(state[14])))^state[14]);
    result[3] = (xtimes_DH(xtimes_DH(xtimes_DH(state[3])))^xtimes_DH(xtimes_DH(state[3]))^xtimes_DH(state[3]))^(xtimes_DH(xtimes_DH(xtimes_DH(state[7])))^xtimes_DH(state[7])^state[7])^(xtimes_DH(xtimes_DH(xtimes_DH(state[11])))^xtimes_DH(xtimes_DH(state[11]))^state[11])^(xtimes_DH(xtimes_DH(xtimes_DH(state[15])))^state[15]);

    result[4] = (xtimes_DH(xtimes_DH(xtimes_DH(state[0])))^state[0])^(xtimes_DH(xtimes_DH(xtimes_DH(state[4])))^xtimes_DH(xtimes_DH(state[4]))^xtimes_DH(state[4]))^(xtimes_DH(xtimes_DH(xtimes_DH(state[8])))^xtimes_DH(state[8])^state[8])^(xtimes_DH(xtimes_DH(xtimes_DH(state[12])))^xtimes_DH(xtimes_DH(state[12]))^state[12]);
    result[5] = (xtimes_DH(xtimes_DH(xtimes_DH(state[1])))^state[1])^(xtimes_DH(xtimes_DH(xtimes_DH(state[5])))^xtimes_DH(xtimes_DH(state[5]))^xtimes_DH(state[5]))^(xtimes_DH(xtimes_DH(xtimes_DH(state[9])))^xtimes_DH(state[9])^state[9])^(xtimes_DH(xtimes_DH(xtimes_DH(state[13])))^xtimes_DH(xtimes_DH(state[13]))^state[13]);
    result[6] = (xtimes_DH(xtimes_DH(xtimes_DH(state[2])))^state[2])^(xtimes_DH(xtimes_DH(xtimes_DH(state[6])))^xtimes_DH(xtimes_DH(state[6]))^xtimes_DH(state[6]))^(xtimes_DH(xtimes_DH(xtimes_DH(state[10])))^xtimes_DH(state[10])^state[10])^(xtimes_DH(xtimes_DH(xtimes_DH(state[14])))^xtimes_DH(xtimes_DH(state[14]))^state[14]);
    result[7] = (xtimes_DH(xtimes_DH(xtimes_DH(state[3])))^state[3])^(xtimes_DH(xtimes_DH(xtimes_DH(state[7])))^xtimes_DH(xtimes_DH(state[7]))^xtimes_DH(state[7]))^(xtimes_DH(xtimes_DH(xtimes_DH(state[11])))^xtimes_DH(state[11])^state[11])^(xtimes_DH(xtimes_DH(xtimes_DH(state[15])))^xtimes_DH(xtimes_DH(state[15]))^state[15]);

    result[8] = (xtimes_DH(xtimes_DH(xtimes_DH(state[0])))^xtimes_DH(xtimes_DH(state[0]))^state[0])^(xtimes_DH(xtimes_DH(xtimes_DH(state[4])))^state[4])^(xtimes_DH(xtimes_DH(xtimes_DH(state[8])))^xtimes_DH(xtimes_DH(state[8]))^xtimes_DH(state[8]))^(xtimes_DH(xtimes_DH(xtimes_DH(state[12])))^xtimes_DH(state[12])^state[12]);
    result[9] = (xtimes_DH(xtimes_DH(xtimes_DH(state[1])))^xtimes_DH(xtimes_DH(state[1]))^state[1])^(xtimes_DH(xtimes_DH(xtimes_DH(state[5])))^state[5])^(xtimes_DH(xtimes_DH(xtimes_DH(state[9])))^xtimes_DH(xtimes_DH(state[9]))^xtimes_DH(state[9]))^(xtimes_DH(xtimes_DH(xtimes_DH(state[13])))^xtimes_DH(state[13])^state[13]);
    result[10] = (xtimes_DH(xtimes_DH(xtimes_DH(state[2])))^xtimes_DH(xtimes_DH(state[2]))^state[2])^(xtimes_DH(xtimes_DH(xtimes_DH(state[6])))^state[6])^(xtimes_DH(xtimes_DH(xtimes_DH(state[10])))^xtimes_DH(xtimes_DH(state[10]))^xtimes_DH(state[10]))^(xtimes_DH(xtimes_DH(xtimes_DH(state[14])))^xtimes_DH(state[14])^state[14]);
    result[11] = (xtimes_DH(xtimes_DH(xtimes_DH(state[3])))^xtimes_DH(xtimes_DH(state[3]))^state[3])^(xtimes_DH(xtimes_DH(xtimes_DH(state[7])))^state[7])^(xtimes_DH(xtimes_DH(xtimes_DH(state[11])))^xtimes_DH(xtimes_DH(state[11]))^xtimes_DH(state[11]))^(xtimes_DH(xtimes_DH(xtimes_DH(state[15])))^xtimes_DH(state[15])^state[15]);

    result[12] = (xtimes_DH(xtimes_DH(xtimes_DH(state[0])))^xtimes_DH(state[0])^state[0])^(xtimes_DH(xtimes_DH(xtimes_DH(state[4])))^xtimes_DH(xtimes_DH(state[4]))^state[4])^(xtimes_DH(xtimes_DH(xtimes_DH(state[8])))^state[8])^(xtimes_DH(xtimes_DH(xtimes_DH(state[12])))^xtimes_DH(xtimes_DH(state[12]))^xtimes_DH(state[12]));
    result[13] = (xtimes_DH(xtimes_DH(xtimes_DH(state[1])))^xtimes_DH(state[1])^state[1])^(xtimes_DH(xtimes_DH(xtimes_DH(state[5])))^xtimes_DH(xtimes_DH(state[5]))^state[5])^(xtimes_DH(xtimes_DH(xtimes_DH(state[9])))^state[9])^(xtimes_DH(xtimes_DH(xtimes_DH(state[13])))^xtimes_DH(xtimes_DH(state[13]))^xtimes_DH(state[13]));
    result[14] = (xtimes_DH(xtimes_DH(xtimes_DH(state[2])))^xtimes_DH(state[2])^state[2])^(xtimes_DH(xtimes_DH(xtimes_DH(state[6])))^xtimes_DH(xtimes_DH(state[6]))^state[6])^(xtimes_DH(xtimes_DH(xtimes_DH(state[10])))^state[10])^(xtimes_DH(xtimes_DH(xtimes_DH(state[14])))^xtimes_DH(xtimes_DH(state[14]))^xtimes_DH(state[14]));
    result[15] = (xtimes_DH(xtimes_DH(xtimes_DH(state[3])))^xtimes_DH(state[3])^state[3])^(xtimes_DH(xtimes_DH(xtimes_DH(state[7])))^xtimes_DH(xtimes_DH(state[7]))^state[7])^(xtimes_DH(xtimes_DH(xtimes_DH(state[11])))^state[11])^(xtimes_DH(xtimes_DH(xtimes_DH(state[15])))^xtimes_DH(xtimes_DH(state[15]))^xtimes_DH(state[15]));

    for(int cnt_i = 0; cnt_i < 16; cnt_i++)
    {
        state[cnt_i] = result[cnt_i];
    }
}



uint32_t SubWord(uint32_t word) { // AddRoundKey 에 필요한 비선형 함수
    uint8_t temp;
    uint8_t word_temp[4] = { 0x00, };

    word_temp[0] = word >> 24;
    word_temp[1] = word >> 16;
    word_temp[2] = word >> 8;
    word_temp[3] = word;

    temp = word_temp[0];
    word_temp[0] = S_Box(word_temp[1]);
    word_temp[1] = S_Box(word_temp[2]);
    word_temp[2] = S_Box(word_temp[3]);
    word_temp[3] = S_Box(temp);

    return (word_temp[0] << 24) ^ (word_temp[1] << 16) ^ (word_temp[2] << 8) ^ (word_temp[3]);
}

void change_Mat(uint8_t* RK_temp) 
{
    uint8_t temp;

    temp = RK_temp[1];
    RK_temp[1] = RK_temp[4];
    RK_temp[4] = temp;

    temp = RK_temp[2];
    RK_temp[2] = RK_temp[8];
    RK_temp[8] = temp;

    temp = RK_temp[3];
    RK_temp[3] = RK_temp[12];
    RK_temp[12] = temp;

    temp = RK_temp[6];
    RK_temp[6] = RK_temp[9];
    RK_temp[9] = temp;

    temp = RK_temp[7];
    RK_temp[7] = RK_temp[13];
    RK_temp[13] = temp;

    temp = RK_temp[11];
    RK_temp[11] = RK_temp[14];
    RK_temp[14] = temp;
}

void AddRoundKey(uint8_t* key, uint32_t* RK, size_t keyLen) { // 1 byte x 16 입력으로 32-bit x 44(총 11라운드) 라운드키 출력
    uint32_t temp;
    uint32_t key_temp[4];
    uint8_t RK_temp[4096] = { 0x00, };

    int cnt_i = 0, cnt_j  = 0;

    byteToInt(key, key_temp);
    

    RK[0] = key_temp[0]; 
    RK[1] = key_temp[1];
    RK[2] = key_temp[2];
    RK[3] = key_temp[3];

    for(cnt_j = 1; cnt_j < 11; cnt_j++)
    {
        temp = SubWord(RK[3 + (cnt_j - 1) * 4]) ^ RC[cnt_j];

        RK[0 + cnt_j * 4] = temp ^ RK[0 + (cnt_j - 1) * 4];
        RK[1 + cnt_j * 4] = RK[0 + cnt_j * 4] ^ RK[1 + (cnt_j - 1) * 4];
        RK[2 + cnt_j * 4] = RK[1 + cnt_j * 4] ^ RK[2 + (cnt_j - 1) * 4];
        RK[3 + cnt_j * 4] = RK[2 + cnt_j * 4] ^ RK[3 + (cnt_j - 1) * 4];
    }

    for(int cnt_i = 0; cnt_i < 11; cnt_i++)
    {
        intToByte(RK + cnt_i * 4, RK_temp + cnt_i * 16);
        change_Mat(RK_temp + cnt_i * 16);
        byteToInt(RK_temp + cnt_i * 16, RK + cnt_i * 4);
    }
}

uint32_t RK[] = {
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

void AES_Encryption(uint8_t* state, uint8_t* key, size_t keyLen, uint8_t* ct) { // 한블럭 암호화
    int cnt_i = 0, cnt_j;
    uint32_t state_temp[4] = { 0x00, };
    
    change_Mat(state);

    byteToInt(state, state_temp);

    //AddRoundKey(key, RK, keyLen); // 라운드키 생성

    state_temp[0] = state_temp[0] ^ RK[0 + cnt_i * 4];
    state_temp[1] = state_temp[1] ^ RK[1 + cnt_i * 4];
    state_temp[2] = state_temp[2] ^ RK[2 + cnt_i * 4];
    state_temp[3] = state_temp[3] ^ RK[3 + cnt_i * 4];

    intToByte(state_temp, state);

    printf("after addroundkey\n");
    for(int cnt_j = 0; cnt_j < 16; cnt_j++)
    {
        printf("%02x ", state[cnt_j]);
        if(cnt_j % 4 == 3) printf("\n");
    }

    for(cnt_i = 1; cnt_i < 10; cnt_i++) // 1 Round ~ 9 Round
    {
        SubBytes(state);

         printf("\nafter subbytes\n");
        for(int cnt_j = 0; cnt_j < 16; cnt_j++)
        {
            printf("%02x ", state[cnt_j]);
            if(cnt_j % 4 == 3) printf("\n");
        }
        ShiftRows(state);
        printf("after shiftRows\n");
        for(int cnt_j = 0; cnt_j < 16; cnt_j++)
        {
            printf("%02x ", state[cnt_j]);
            if(cnt_j % 4 == 3) printf("\n");
        }
        MixColumn(state);
        printf("after mixcolumns\n");
        for(int cnt_j = 0; cnt_j < 16; cnt_j++)
        {
            printf("%02x ", state[cnt_j]);
            if(cnt_j % 4 == 3) printf("\n");
        }

        byteToInt(state, state_temp); // RK XOR state 를 위해 state 를 32-bit 배열로 변환

        state_temp[0] = state_temp[0] ^ RK[0 + cnt_i * 4];
        state_temp[1] = state_temp[1] ^ RK[1 + cnt_i * 4];
        state_temp[2] = state_temp[2] ^ RK[2 + cnt_i * 4];
        state_temp[3] = state_temp[3] ^ RK[3 + cnt_i * 4];

        intToByte(state_temp, state);

        printf("after addroundkey\n");
        for(int cnt_j = 0; cnt_j < 16; cnt_j++)
        {
            printf("%02x ", state[cnt_j]);
            if(cnt_j % 4 == 3) printf("\n");
        }
    }

    // 10 Round (MixColumns 을 진행하지 않음)
    SubBytes(state); 
    printf("after subbytes\n");
        for(int cnt_j = 0; cnt_j < 16; cnt_j++)
        {
            printf("%02x ", state[cnt_j]);
            if(cnt_j % 4 == 3) printf("\n");
        }
    ShiftRows(state);
    printf("after shiftRows\n");
        for(int cnt_j = 0; cnt_j < 16; cnt_j++)
        {
            printf("%02x ", state[cnt_j]);
            if(cnt_j % 4 == 3) printf("\n");
        }

    byteToInt(state, state_temp);

    state_temp[0] = state_temp[0] ^ RK[40];
    state_temp[1] = state_temp[1] ^ RK[41];
    state_temp[2] = state_temp[2] ^ RK[42];
    state_temp[3] = state_temp[3] ^ RK[43];

    intToByte(state_temp, state);
    printf("after addRoundkey\n");
        for(int cnt_j = 0; cnt_j < 16; cnt_j++)
        {
            printf("%02x ", state[cnt_j]);
            if(cnt_j % 4 == 3) printf("\n");
        }

    for(cnt_j = 0; cnt_j < 16; cnt_j++)
    {
        ct[cnt_j] = state[cnt_j];
    }

    change_Mat(ct);
}

void AES_Decryption(uint8_t* state, uint8_t* key, size_t keyLen, uint8_t* pt) { // 한블럭 복호화
    int cnt_i = 0, cnt_j = 0;
    uint32_t RK[1024] = { 0x00, };
    uint32_t state_temp[4] = { 0x00, };

    change_Mat(state);

    AddRoundKey(key, RK, keyLen);

    byteToInt(state, state_temp);

    state_temp[0] = state_temp[0] ^ RK[40];
    state_temp[1] = state_temp[1] ^ RK[41];
    state_temp[2] = state_temp[2] ^ RK[42];
    state_temp[3] = state_temp[3] ^ RK[43];

    intToByte(state_temp, state);

    for(cnt_i = 9; cnt_i >= 1; cnt_i--)
    {
        Inv_ShiftRows(state);

        for(cnt_j = 0; cnt_j < 16; cnt_j++)
        {
            state[cnt_j] = Inv_S_box[state[cnt_j]];
        }

        byteToInt(state, state_temp);

        state_temp[0] = state_temp[0] ^ RK[0 + cnt_i * 4];
        state_temp[1] = state_temp[1] ^ RK[1 + cnt_i * 4];
        state_temp[2] = state_temp[2] ^ RK[2 + cnt_i * 4];
        state_temp[3] = state_temp[3] ^ RK[3 + cnt_i * 4];

        intToByte(state_temp, state);

        Inv_MixColumn(state);
    }

    Inv_ShiftRows(state);

    for(cnt_j = 0; cnt_j < 16; cnt_j++)
    {
        state[cnt_j] = Inv_S_box[state[cnt_j]];
    }

    byteToInt(state, state_temp);

    state_temp[0] = state_temp[0] ^ RK[0];
    state_temp[1] = state_temp[1] ^ RK[1];
    state_temp[2] = state_temp[2] ^ RK[2];
    state_temp[3] = state_temp[3] ^ RK[3];

    intToByte(state_temp, state);

    for(cnt_j = 0; cnt_j < 16; cnt_j++)
    {
        pt[cnt_j] = state[cnt_j];
    }

    change_Mat(pt);
}

void AES_BlockCipher(int direct, int mode, uint8_t* pt, size_t ptLen, uint8_t* key, size_t keyLen, uint8_t* ct, size_t ctLen, uint8_t* IV)
{
    int numOfBlock;
    int cnt_i, cnt_j, cnt_k;

    uint8_t IV_temp[16]; // CTR mode 에서 카운터 증가 저장용

    switch (direct)
    {
    case ENCRYPT:
        if(mode == MODE_ECB) // 한블럭에 대해서만 수행
        {
            AES_Encryption(pt, key, keyLen, ct);
        }
        else if(mode == MODE_CBC) 
        {
            numOfBlock = ptLen / 16;

            for(cnt_i = 0; cnt_i < numOfBlock; cnt_i++)
            {
                if(cnt_i == 0) // 첫번째 평문 블럭 XOR IV 후 암호화
                {
                    for(cnt_j = 0; cnt_j < 16; cnt_j++) 
                    {
                        pt[cnt_j] ^= IV[cnt_j];
                    }
                    AES_Encryption(pt, key, keyLen, ct);
                }
                else // 두번째 블럭부터 마지막 블럭까지 XOR 이전 암호문 후 암호화
                {
                    for(cnt_j = 0; cnt_j < 16; cnt_j++)
                    {
                        pt[cnt_j + cnt_i * 16] ^= ct[cnt_j + (cnt_i - 1) * 16];
                    }
                    AES_Encryption(pt + (cnt_i * 16), key, keyLen, ct + (cnt_i * 16));
                }
            }
        }
        else if(mode == MODE_CTR)
        {
            numOfBlock = ptLen / 16;

            for(int cnt_i = 0; cnt_i < 16; cnt_i++)
            {
                IV_temp[cnt_i] = IV[cnt_i]; // IV_temp : 카운터 증가 용 변수
            }

            for(cnt_i = 0; cnt_i < numOfBlock; cnt_i++)
            {
                AES_Encryption(IV, key, keyLen, IV); // IV 암호화

                for(cnt_j = 0; cnt_j < 16; cnt_j++)
                {
                    ct[cnt_j + cnt_i * 16] = pt[cnt_j + cnt_i * 16] ^ IV[cnt_j];
                }

                for(int cnt_j = 15; cnt_j >= 0; cnt_j--) // IV + 1
                {
                    IV_temp[cnt_j] += 0x01;
                    if(IV_temp[cnt_j] != 0x00) break;
                }

                for(int cnt_j = 0; cnt_j < 16; cnt_j++) // 1 증가한 IV_temp 를 IV에 대입
                {
                    IV[cnt_j] = IV_temp[cnt_j];
                }
            }   
        }
        break;
    
    case DECRYPT:
        if(mode == MODE_ECB)
        {
            AES_Decryption(ct, key, keyLen, pt);
        }
        else if(mode == MODE_CBC)
        {
            numOfBlock = ctLen / 16;

            for(cnt_i = numOfBlock - 1; cnt_i >= 0; cnt_i--)
            {
                if(cnt_i == 0) // 첫번째 블럭 복호화
                {
                    AES_Decryption(ct, key, keyLen, pt);
                    for(cnt_j = 0; cnt_j < 16; cnt_j++)
                    {
                        pt[cnt_j] ^= IV[cnt_j];
                    }
                }
                else
                {
                    AES_Decryption(ct + (cnt_i * 16), key, keyLen, pt + (cnt_i * 16));
                    for(cnt_j = 0; cnt_j < 16; cnt_j++)
                    {
                        pt[cnt_j + (cnt_i * 16)] ^= ct[cnt_j + (cnt_i - 1) * 16];
                    }
                }
            }

        }
        else if(mode == MODE_CTR)
        {
            numOfBlock = ptLen / 16;

            for(int cnt_i = 0; cnt_i < 16; cnt_i++)
            {
                IV_temp[cnt_i] = IV[cnt_i];
            }

            for(cnt_i = 0; cnt_i < numOfBlock; cnt_i++)
            {
                AES_Encryption(IV, key, keyLen, IV);

                printf("IV[%d] : ", cnt_i);
                for(int cnt_j = 0; cnt_j < 16; cnt_j++)
                {
                    printf("%02x ", IV[cnt_j]);
                }
                printf("\n\n");
                

                for(cnt_j = 0; cnt_j < 16; cnt_j++)
                {
                    pt[cnt_j + cnt_i * 16] =  ct[cnt_j + cnt_i * 16] ^ IV[cnt_j];
                }

                for(int cnt_j = 15; cnt_j >= 0; cnt_j--)
                {
                    IV_temp[cnt_j] += 0x01;
                    if(IV_temp[cnt_j] != 0x00) break;
                }

                for(int cnt_j = 0; cnt_j < 16; cnt_j++)
                {
                    IV[cnt_j] = IV_temp[cnt_j];
                }
            }   
        }
        break;

    default:
        break;
    }
}

int main()
{
    //*ECB_TEST VECTOR_1
    // uint8_t key[16] = { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
    // uint8_t state_pt[16] = { 0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34 };
    // uint8_t state_ct[16] = { 0x39, 0x25, 0x84, 0x1d, 0x02, 0xdc, 0x09, 0xfb, 0xdc, 0x11, 0x85, 0x97, 0x19, 0x6a, 0x0b, 0x32 };
    // uint8_t pt[16] = { 0x00, };
    // uint8_t ct[16] = { 0x00, };
    
    //*ECB_TEST VECTOR_2
    // uint8_t key[16] = { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c };
    // uint8_t state_pt[16] =  { 0x6b ,0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a };
    // uint8_t state_ct[16] = { 0x3a, 0xd7, 0x7b, 0xb4, 0x0d, 0x7a, 0x36, 0x60, 0xa8, 0x9e, 0xca, 0xf3, 0x24, 0x66, 0xef, 0x97 };
    // uint8_t pt[16] = { 0x00, };
    // uint8_t ct[16] = { 0x00, };


    //*CBC_TEST VECTOR
    // uint8_t key[16] = { 0x42, 0x78, 0xb8, 0x40, 0xfb, 0x44, 0xaa, 0xa7, 0x57, 0xc1, 0xbf, 0x04, 0xac, 0xbe, 0x1a, 0x3e };
    // uint8_t IV[16] = { 0x57, 0xf0, 0x2a, 0x5c, 0x53, 0x39, 0xda, 0xeb, 0x0a, 0x29, 0x08, 0xa0, 0x6a, 0xc6, 0x39, 0x3f };
    // uint8_t state_pt[32] = { 0x3c, 0x88, 0x8b, 0xbb, 0xb1, 0xa8, 0xeb, 0x9f, 0x3e, 0x9b, 0x87, 0xac, 0xaa, 0xd9, 0x86, 0xc4, 0x66, 0xe2, 0xf7, 0x07, 0x1c, 0x83, 0x08, 0x3b, 0x8a, 0x55, 0x79, 0x71, 0x91, 0x88, 0x50, 0xe5 };
    // uint8_t state_ct[32] = { 0x47, 0x9c, 0x89, 0xec, 0x14, 0xbc, 0x98, 0x99, 0x4e, 0x62, 0xb2, 0xc7, 0x05, 0xb5, 0x01, 0x4e, 0x17, 0x5b, 0xd7, 0x83, 0x2e, 0x7e, 0x60, 0xa1, 0xe9, 0x2a, 0xac, 0x56, 0x8a, 0x86, 0x1e, 0xb7 };
    // uint8_t pt[32] = { 0x00, };
    // uint8_t ct[32] = { 0x00, };

    // uint8_t key[16] = {};
    // uint8_t IV[16] = {};
    // uint8_t state_pt[16] = {};
    // uint8_t state_ct[16] = {};
    // uint8_t pt[32] = { 0x00, };
    // uint8_t ct[32] = { 0x00, };

    uint8_t key[16] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c };
    uint8_t IV[16] = {0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff };
    uint8_t state_pt[32] = {0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a, 0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51 };
    uint8_t state_ct[32] = { 0x87, 0x4d, 0x61, 0x91, 0xb6, 0x20, 0xe3, 0x26, 0x1b, 0xef, 0x68, 0x64, 0x99, 0x0d, 0xb6, 0xce, 0x98, 0x06, 0xf6, 0x6b, 0x79, 0x70, 0xfd, 0xff, 0x86, 0x17, 0x18, 0x7b, 0xb9, 0xff, 0xfd, 0xff };
    uint8_t pt[32] = { 0x00, };
    uint8_t ct[32] = { 0x00, };

    //*CTR_TEST VECTOR
    // uint8_t key[16] = {};
    // uint8_t IV[16] = {};
    // uint8_t state_pt[16] = {};
    // uint8_t state_ct[16] = {};
    // uint8_t pt[32] = { 0x00, };
    // uint8_t ct[32] = { 0x00, };


    AES_BlockCipher(ENCRYPT, MODE_CTR, state_pt, sizeof(state_pt), key, 16, ct, sizeof(ct), IV);
    AES_BlockCipher(DECRYPT, MODE_CTR, pt, sizeof(pt), key, 16, state_ct, sizeof(state_ct), IV);

    printf("\n<ct>\n");
    for(int cnt_j = 0; cnt_j < 32; cnt_j++)
    {
        printf("%02x ", ct[cnt_j]);
    }
    printf("\n");

    printf("\n<pt>\n");
    for(int cnt_j = 0; cnt_j < 32; cnt_j++)
    {
        printf("%02x ", pt[cnt_j]);
    }
    printf("\n");

    return 0;
}
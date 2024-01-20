.section .data
MC_RES: .space 16

.section .text
AES_SBOX:
    .byte   0x63,   0x7c,   0x77,   0x7b
    .byte   0xf2,   0x6b,   0x6f,   0xc5
    .byte   0x30,   0x1,    0x67,   0x2b
    .byte   0xfe,   0xd7,   0xab,   0x76
    .byte   0xca,   0x82,   0xc9,   0x7d
    .byte   0xfa,   0x59,   0x47,   0xf0
    .byte   0xad,   0xd4,   0xa2,   0xaf
    .byte   0x9c,   0xa4,   0x72,   0xc0
    .byte   0xb7,   0xfd,   0x93,   0x26
    .byte   0x36,   0x3f,   0xf7,   0xcc
    .byte   0x34,   0xa5,   0xe5,   0xf1
    .byte   0x71,   0xd8,   0x31,   0x15
    .byte   0x4,    0xc7,   0x23,   0xc3
    .byte   0x18,   0x96,   0x5,    0x9a
    .byte   0x7,    0x12,   0x80,   0xe2
    .byte   0xeb,   0x27,   0xb2,   0x75
    .byte   0x9,    0x83,   0x2c,   0x1a
    .byte   0x1b,   0x6e,   0x5a,   0xa0
    .byte   0x52,   0x3b,   0xd6,   0xb3
    .byte   0x29,   0xe3,   0x2f,   0x84
    .byte   0x53,   0xd1,   0x0,    0xed
    .byte   0x20,   0xfc,   0xb1,   0x5b
    .byte   0x6a,   0xcb,   0xbe,   0x39
    .byte   0x4a,   0x4c,   0x58,   0xcf
    .byte   0xd0,   0xef,   0xaa,   0xfb
    .byte   0x43,   0x4d,   0x33,   0x85
    .byte   0x45,   0xf9,   0x2,    0x7f
    .byte   0x50,   0x3c,   0x9f,   0xa8
    .byte   0x51,   0xa3,   0x40,   0x8f
    .byte   0x92,   0x9d,   0x38,   0xf5
    .byte   0xbc,   0xb6,   0xda,   0x21
    .byte   0x10,   0xff,   0xf3,   0xd2
    .byte   0xcd,   0xc,    0x13,   0xec
    .byte   0x5f,   0x97,   0x44,   0x17
    .byte   0xc4,   0xa7,   0x7e,   0x3d
    .byte   0x64,   0x5d,   0x19,   0x73
    .byte   0x60,   0x81,   0x4f,   0xdc
    .byte   0x22,   0x2a,   0x90,   0x88
    .byte   0x46,   0xee,   0xb8,   0x14
    .byte   0xde,   0x5e,   0xb,    0xdb
    .byte   0xe0,   0x32,   0x3a,   0xa
    .byte   0x49,   0x6,    0x24,   0x5c
    .byte   0xc2,   0xd3,   0xac,   0x62
    .byte   0x91,   0x95,   0xe4,   0x79
    .byte   0xe7,   0xc8,   0x37,   0x6d
    .byte   0x8d,   0xd5,   0x4e,   0xa9
    .byte   0x6c,   0x56,   0xf4,   0xea
    .byte   0x65,   0x7a,   0xae,   0x8
    .byte   0xba,   0x78,   0x25,   0x2e
    .byte   0x1c,   0xa6,   0xb4,   0xc6
    .byte   0xe8,   0xdd,   0x74,   0x1f
    .byte   0x4b,   0xbd,   0x8b,   0x8a
    .byte   0x70,   0x3e,   0xb5,   0x66
    .byte   0x48,   0x3,    0xf6,   0xe
    .byte   0x61,   0x35,   0x57,   0xb9
    .byte   0x86,   0xc1,   0x1d,   0x9e
    .byte   0xe1,   0xf8,   0x98,   0x11
    .byte   0x69,   0xd9,   0x8e,   0x94
    .byte   0x9b,   0x1e,   0x87,   0xe9
    .byte   0xce,   0x55,   0x28,   0xdf
    .byte   0x8c,   0xa1,   0x89,   0xd
    .byte   0xbf,   0xe6,   0x42,   0x68
    .byte   0x41,   0x99,   0x2d,   0xf
    .byte   0xb0,   0x54,   0xbb,   0x16


.global SubBytes
.type SubBytes, @function
SubBytes:
    # void SubBytes(uint8_t* state)

    # Register Usage
    # a0: function parameter
    # t0: loop counter
    # t1: array index
    # t2: max counter
    # t3: temporary
    # t4: temporary
    # t5: state address
    # t6: Sbox address

    # initialize
    li  t0, 0   # loop counter
    li  t2, 16   # loop counter

SB_LOOP:
    li  t3, 0
    li  t4, 0
    # load address of Sbox
    la  t6, AES_SBOX

    # load address of state
    mv  t5, a0

    # load state[i]
    add t5, t5, t0
    lbu  t3, 0(t5)

    # load Sbox[state[i]]
    add t4, t6, t3
    lbu  t3, 0(t4)

    # store
    sb  t3, 0(t5)

    # check loop condition
    addi t0, t0, 1
    blt t0, t2, SB_LOOP 

    ret
    

.global ShiftRows
.type ShiftRows, @function
ShiftRows:
    # void SubBytes(uint8_t* state)

    #   0 4 8  12       0  4  8  12
    #   1 5 9  13   ->  5  9  13 1
    #   2 6 10 14       10 14 2  6
    #   3 7 11 15       15 3  7  11
 
    # Register Usage
    # a0: function parameter
    # a7: temporary
    # t2: state 4, 8, 12
    # t3: state 5, 9, 13 
    # t4: state 6, 10, 14 
    # t5: state 7, 11, 15 

    # SR 1
    # load elements
    lbu t2, 1(a0)   # state[4] (tmp)
    lbu t3, 5(a0)   # state[5]
    lbu t4, 9(a0)   # state[6]
    lbu t5, 13(a0)  # state[7]

    mv  a7, t2  # tmp <- state[4]
    mv  t2, t3  # state[4] <- state[5]
    mv  t3, t4  # state[5] <- state[6]
    mv  t4, t5  # state[6] <- state[7]
    mv  t5, a7  # state[7] <- tmp

    sb  t2, 1(a0)
    sb  t3, 5(a0)
    sb  t4, 9(a0)
    sb  t5, 13(a0)


    # SR 2
    # load elements
    lbu t2, 2(a0)   # state[8] (tmp)
    lbu t3, 6(a0)   # state[9]
    lbu t4, 10(a0)   # state[10]
    lbu t5, 14(a0)   # state[11]

    mv  a7, t2  # tmp <- state[8]
    mv  t2, t4  # state[8] <- state[10]
    mv  t4, a7  # state[10] <- tmp
    mv  a7, t3  # tmp <- state[9]
    mv  t3, t5  # state[9] <- state[11]
    mv  t5, a7  # state[11] <- tmp

    sb  t2, 2(a0)
    sb  t3, 6(a0)
    sb  t4, 10(a0)
    sb  t5, 14(a0)

    # SR 3
    # load elements
    lbu t2, 3(a0)    # state[12] (tmp)
    lbu t3, 7(a0)    # state[13]
    lbu t4, 11(a0)   # state[14]
    lbu t5, 15(a0)   # state[15]

    mv  a7, t5  # tmp <- state[15]
    mv  t5, t4  # state[15] <- state[14]
    mv  t4, t3  # state[14] <- state[13]
    mv  t3, t2  # state[13] <- state[12]
    mv  t2, a7  # state[12] <- tmp

    sb  t2, 3(a0) 
    sb  t3, 7(a0) 
    sb  t4, 11(a0)
    sb  t5, 15(a0)

    ret

.macro xtimes f
    li  a3, 0x1b
    slli a1, \f, 1  # f << 1
    srli a2, \f, 7  # f >> 7
    mul a2, a2, a3  # (f >> 7) * 0x1b
    xor \f, a1, a2  # (f << 1) ^ ((f >> 7) * 0x1b)
.endm


.global MixColumn
.type MixColumn, @function
MixColumn:
    # void MixColumn(uint8_t* state)

    # Register Usage
    # a0: function parameter (state)
    # a1: temporary for xtimes
    # a2: temporary for xtimes
    # a3: temporary for xtimes
    # t0: state address
    # t1: res address
    # t2: temporary
    # t3: temporary
    # t4: array index
    # t5: max loop counter (16)
    # t6: loop counter

    # load address of MC_RES and state
    la  t1, MC_RES
    mv  t0, a0

    # res[0]
    lbu t2, 0(t0)
    xtimes t2   # xtimes(state[0])
    lbu t3, 1(t0)
    xtimes t3   # xtimes(state[4])
    xor t2, t2, t3 # xtimes(state[0]) ^ xtimes(state[4])
    lbu t3, 1(t0)
    xor t2, t2, t3 # xtimes(state[0]) ^ xtimes(state[4]) ^ state[4]
    lbu t3, 2(t0)
    xor t2, t2, t3
    lbu t3, 3(t0)
    xor t2, t2, t3
    sb  t2, 0(t1)

    # res[1]
    lbu t2, 4(t0)
    xtimes t2  
    lbu t3, 5(t0)
    xtimes t3  
    xor t2, t2, t3 
    lbu t3, 5(t0)
    xor t2, t2, t3 
    lbu t3, 6(t0)
    xor t2, t2, t3
    lbu t3, 7(t0)
    xor t2, t2, t3
    sb  t2, 4(t1)

    # res[2]
    lbu t2, 8(t0)
    xtimes t2   
    lbu t3, 9(t0)
    xtimes t3   
    xor t2, t2, t3 
    lbu t3, 9(t0)
    xor t2, t2, t3 
    lbu t3, 10(t0)
    xor t2, t2, t3
    lbu t3, 11(t0)
    xor t2, t2, t3
    sb  t2, 4(t1)

    # res[3]
    lbu t2, 12(t0)
    xtimes t2  
    lbu t3, 13(t0)
    xtimes t3  
    xor t2, t2, t3 
    lbu t3, 13(t0)
    xor t2, t2, t3 
    lbu t3, 14(t0)
    xor t2, t2, t3
    lbu t3, 15(t0)
    xor t2, t2, t3
    sb  t2, 12(t1)

    # res[4]
    lbu t2, 0(t0)   # state[0]
    lbu t3, 1(t0)   
    xtimes t3   # state[0] ^ xtimes(state[4])
    xor t2, t2, t3
    lbu t3, 2(t0)
    xor t2, t2, t3
    xtimes t3
    xor t2, t2, t3  # state[0] ^ xtimes(state[4]) ^ (xtimes(state[8]) ^ state[8])
    lbu t3, 3(t0)
    xor t2, t2, t3
    sb  t2, 1(t1)

    # res[5]
    lbu t2, 4(t0)   # state[0]
    lbu t3, 5(t0)   
    xtimes t3   # state[0] ^ xtimes(state[4])
    xor t2, t2, t3
    lbu t3, 6(t0)
    xor t2, t2, t3
    xtimes t3
    xor t2, t2, t3  # state[0] ^ xtimes(state[4]) ^ (xtimes(state[8]) ^ state[8])
    lbu t3, 7(t0)
    xor t2, t2, t3
    sb  t2, 5(t1)

    # res[6]
    lbu t2, 8(t0)   # state[0]
    lbu t3, 9(t0)   
    xtimes t3   # state[0] ^ xtimes(state[4])
    xor t2, t2, t3
    lbu t3, 10(t0)
    xor t2, t2, t3
    xtimes t3
    xor t2, t2, t3  # state[0] ^ xtimes(state[4]) ^ (xtimes(state[8]) ^ state[8])
    lbu t3, 11(t0)
    xor t2, t2, t3
    sb  t2, 9(t1)

    # res[7]
    lbu t2, 12(t0)   # state[0]
    lbu t3, 13(t0)   
    xtimes t3   # state[0] ^ xtimes(state[4])
    xor t2, t2, t3
    lbu t3, 14(t0)
    xor t2, t2, t3
    xtimes t3
    xor t2, t2, t3  # state[0] ^ xtimes(state[4]) ^ (xtimes(state[8]) ^ state[8])
    lbu t3, 15(t0)
    xor t2, t2, t3
    sb  t2, 13(t1)

    # res[8]
    lbu t2, 0(t0)
    lbu t3, 1(t0)
    xor t2, t2, t3  
    lbu t3, 2(t0)
    xtimes t3
    xor t2, t2, t3
    lbu t3, 3(t0)
    xor t2, t2, t3
    xtimes t3
    xor t2, t2, t3
    sb  t2, 2(t1)

    # res[9]
    lbu t2, 4(t0)
    lbu t3, 5(t0)
    xor t2, t2, t3  
    lbu t3, 6(t0)
    xtimes t3
    xor t2, t2, t3
    lbu t3, 7(t0)
    xor t2, t2, t3
    xtimes t3
    xor t2, t2, t3
    sb  t2, 6(t1)

    # res[10]
    lbu t2, 8(t0)
    lbu t3, 9(t0)
    xor t2, t2, t3  
    lbu t3, 10(t0)
    xtimes t3
    xor t2, t2, t3
    lbu t3, 11(t0)
    xor t2, t2, t3
    xtimes t3
    xor t2, t2, t3
    sb  t2, 10(t1)

    # res[11]
    lbu t2, 12(t0)
    lbu t3, 13(t0)
    xor t2, t2, t3  
    lbu t3, 14(t0)
    xtimes t3
    xor t2, t2, t3
    lbu t3, 15(t0)
    xor t2, t2, t3
    xtimes t3
    xor t2, t2, t3
    sb  t2, 14(t1)

    # res[12]
    lbu t2, 0(t0)
    xtimes t2
    lbu t3, 0(t0)
    xor t2, t2, t3
    lbu t3, 1(t0)
    xor t2, t2, t3
    lbu t3, 2(t0)
    xor t2, t2, t3
    lbu t3, 3(t0)
    xtimes t3
    xor t2, t2, t3
    sb  t2, 3(t1)

    # res[13]
    lbu t2, 4(t0)
    xtimes t2
    lbu t3, 4(t0)
    xor t2, t2, t3
    lbu t3, 5(t0)
    xor t2, t2, t3
    lbu t3, 6(t0)
    xor t2, t2, t3
    lbu t3, 7(t0)
    xtimes t3
    xor t2, t2, t3
    sb  t2, 7(t1)

    # res[14]
    lbu t2, 8(t0)
    xtimes t2
    lbu t3, 8(t0)
    xor t2, t2, t3
    lbu t3, 9(t0)
    xor t2, t2, t3
    lbu t3, 10(t0)
    xor t2, t2, t3
    lbu t3, 11(t0)
    xtimes t3
    xor t2, t2, t3
    sb  t2, 11(t1)

    # res[15]
    lbu t2, 12(t0)
    xtimes t2
    lbu t3, 12(t0)
    xor t2, t2, t3
    lbu t3, 13(t0)
    xor t2, t2, t3
    lbu t3, 14(t0)
    xor t2, t2, t3
    lbu t3, 15(t0)
    xtimes t3
    xor t2, t2, t3
    sb  t2, 15(t1)

    # copt res to state
    li  t5, 16  # max loop counter
    li  t6, 0   # loop counter
    li  t4, 0   # array index
    mv  t0, a0

MC_LOOP2:
    lbu t2, 0(t1)
    sb  t2, 0(t0)

    addi t6, t6, 1
    addi t1, t1, 1
    addi t0, t0, 1
    blt t6, t5, MC_LOOP2

    ret

.global AddRoundKey
.type AddRoundKey, @function
AddRoundKey:
    # void AddRoundKey(uint8_t* state, uint8_t* rk)

    # Register Usage
    # a0: function parameter (state)
    # a1: function parameter (rk)
    # t0: state address
    # t1: rk address
    # t2: temporary
    # t3: temporary
    # t4: array index
    # t5: max loop counter (16)
    # t6: loop counter
    

    # initialize
    li  t0, 0   # state index
    li  t1, 0   # rk index
    li  t5, 16  # max loop counter
    li  t6, 0   # loop counter

    # copy address of state and rk
    mv  t0, a0
    mv  t1, a1

ADDRK_LOOP:
    lbu t2, 0(t0)
    lbu t3, 0(t1)
    xor t2, t2, t3  # state[i] <- state[i] ^ rk[i]
    sb  t2, 0(t0)


    # move address 1 byte
    addi t0, t0, 1
    addi t1, t1, 1

    # check loop condition
    addi t6, t6, 1
    blt t6, t5, ADDRK_LOOP

    ret


.global AES_encrypt1
.type AES_encrypt1, @function
AES_encrypt1:
    # void AES_encrypt()
/**
 * @file md5.h
 * @author Luke Early
 * Header file for md5.c
 */

#ifndef _MD5_H_
#define _MD5_H_

#include "block.h"

/** Number of bytes in a MD5 hash */
#define HASH_SIZE 16

/** number of bits in a word */
#define WORD_BIT_SIZE 32

/** number of bit in a byte */
#define BITS_IN_A_BYTE 8

/** Number of bytes that go into a word */
#define NUMBER_OF_BYTES_IN_WORD 4

/** upper limit to pad block with zero's */
#define BLOCK_ZERO_PADDING_LIMIT 56

/** number of iterations in one round */
#define SIZE_OF_ROUND 16

/** number of Round F functions */
#define NUMBER_F_FXNS 4

/** number of Round G functions */
#define NUMBER_G_FXNS 4

/** LSB first flip, Word A first byte index */
#define WORD_A_FIRST_BYTE 0
/** LSB first flip, Word A Last byte index */
#define WORD_A_LAST_BYTE 4

/** LSB first flip, Word B first byte index */
#define WORD_B_FIRST_BYTE 4
/** LSB first flip, Word B Last byte index */
#define WORD_B_LAST_BYTE 8

/** LSB first flip, Word C first byte index */
#define WORD_C_FIRST_BYTE 8
/** LSB first flip, Word C Last byte index */
#define WORD_C_LAST_BYTE 12

/** init value for A */
#define INIT_VALUE_A 0x67452301

/** init value for B */
#define INIT_VALUE_B 0xefcdab89

/** init value for C */
#define INIT_VALUE_C 0x98badcfe

/** init value for D */
#define INIT_VALUE_D 0x10325476

/** first value to add after block's data is complete */
#define FIRST_VALUE_AFTER_DATA 0x80

/** value to pad block data with */
#define BLOCK_DATA_PADDING 0x00

/** Function type for the f functions in the md5 algorithm. */
typedef word (*FFunction)( word, word, word );

/** Function type for the g functions in the md5 algorithm. */
typedef int (*GFunction)( int );

/**
 * First version of F function which combines words A, B,
 * C, and D via bitwise operators.
 * 
 * This round's function is:
 * 
 * F0 = ( B & C ) | ( (~B) & D ) )
 * 
 * @param B word to be combined with C and D
 * @param C word to be combined with B and D
 * @param D word to be combined with B and C
 * 
 * @return new combination of words A, B, C, and D
 */
word fVersion0( word B, word C, word D );

/**
 * Second version of F function which combines words A, B,
 * C, and D via bitwise operators.
 * 
 * This round's function is:
 * 
 * F1 = ( B & D ) | ( C & (~D) )
 * 
 * @param B word to be combined with C and D
 * @param C word to be combined with B and D
 * @param D word to be combined with B and C
 * 
 * @return new combination of words A, B, C, and D
 */
word fVersion1( word B, word C, word D );

/**
 * Third version of F function which combines words A, B,
 * C, and D via bitwise operators.
 * 
 * This round's function is:
 * 
 * F2 = B ^ C ^ D
 * 
 * @param B word to be combined with C and D
 * @param C word to be combined with B and D
 * @param D word to be combined with B and C
 * 
 * @return new combination of words A, B, C, and D
 */
word fVersion2( word B, word C, word D );

/**
 * Final version of F function which combines words A, B,
 * C, and D via bitwise operators.
 * 
 * This round's function is:
 * 
 * F3 = C ^ ( B | (~D) )
 * 
 * @param B word to be combined with C and D
 * @param C word to be combined with B and D
 * @param D word to be combined with B and C
 * 
 * @return new combination of words A, B, C, and D
 */
word fVersion3( word B, word C, word D );

/**
 * This is the first function to determines which of 
 * the 16 words are included in the hash calculation.
 * 
 * G0 = idx
 * 
 * @param idx iteration number
 * 
 * @return index position of word to use
 */
int gVersion0( int idx );

/**
 * This is the second function to determines which of 
 * the 16 words are included in the hash calculation.
 * 
 * G1 = ( 5 * i + 1 ) % 16
 * 
 * @param idx iteration number
 * 
 * @return index position of word to use
 */
int gVersion1( int idx );

/**
 * This is the third function to determines which of 
 * the 16 words are included in the hash calculation.
 * 
 * G2 = ( 3 * i + 5 ) % 16;
 * 
 * @param idx iteration number
 * 
 * @return index position of word to use
 */
int gVersion2( int idx );

/**
 * This is the final function to determines which of 
 * the 16 words are included in the hash calculation.
 * 
 * G3 = ( 7 * i ) % 16;
 * 
 * @param idx iteration number
 * 
 * @return index position of word to use
 */
int gVersion3( int idx );

/**
 * Handles copying the top s bits, shifting the bitstring
 * s bit to the left, and then inserting the bits removed 
 * into the first s low order bits.
 * 
 * @param value bitfield that will be rotated
 * @param s number of bits to rotate left
 * 
 * @return word rotated left by s bits
 */
word rotateLeft( word value, int s );

/**
 * Handles one iteration of MD5 algorithm.
 * 
 * @param M Contents of the block
 * @param A MD5 state represented as a word
 * @param B MD5 state represented as a word
 * @param C MD5 state represented as a word
 * @param D MD5 state represented as a word
 * @param i iteration number, a value between 0 and 63
 */
void md5Iteration( word M[ BLOCK_WORDS ], word *A, word *B, word *C, word *D, int i );

/**
 * Pads block to increase it's length to 64 bytes.
 * 
 * @param block the block which will be padded
 */
void padBlock( Block *block );

/**
 * Pads given input block, computes the MD5 hash with helper functions, 
 * stores the results in a given hash array.
 * 
 * @param block block of data
 * @param hash list of hashes
 */
void md5Hash( Block *block, byte hash[ HASH_SIZE ] );

/**
 * Pads given input block, computes the MD5 hash with helper functions, 
 * stores the results in a given hash array.
 */
void md5Hash( Block *block, byte hash[ HASH_SIZE ] );

#endif

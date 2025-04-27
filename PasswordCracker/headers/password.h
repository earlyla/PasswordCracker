/**
 * @file password.h
 * @author Luke Early
 * Header file for password.c
 */

#ifndef _PASSWORD_H_
#define _PASSWORD_H_

/** Required length of the salt string. */
#define SALT_LENGTH 8

/** Maximum length of a password.  Just to simplify our program; passwords
    aren't really required to be this short. */
#define PW_LIMIT 15

/** Maximum length of a password hash string created by hashPassword() */
#define PW_HASH_LIMIT 22

/** Bit value that indicates a zero byte should be appended */
#define ZERO_BYTE_FLAG 1

/** Bit value that indicates first byte of the block's data should be appended */
#define FIRST_BYTE_FLAG 0

/** Index of first byte of data in block, used during computeFirstIntermediate */
#define FIRST_BYTE_OF_BLOCK_DATA_IDX 0

/**
 * Increment this much in order to find value of next bit
 * 
 * If value is ZERO_BYTE_FLAG, put a 0x00 byte
 * Else, load the first data byte in block
 */
#define SINGLE_BIT_MOVEMENT 1

/** number of rounds required to get all binary letters extracted from byte string */
#define BYTE_TO_CHAR_TRANSLATION_ROUNDS 6

/** number of bytes per translations set */
#define SET_OF_BYTES 3

/** Number of bits that represent a letter */
#define BITS_IN_LETTER 6

/** Leftover bits that go in the most significant position */
#define LEFTOVER_BITS_MSB 2

/** Leftover bits that go in the least significant position */
#define LEFTOVER_BITS_LSB 2

/** Leftover bits in the middle */
#define LEFTOVER_BITS_MIDDLE 4

/** Mask for bits excpet 2 msb */
#define BITS_MASK_MSB 0x3F

/** second byte in sets of 3 */
#define SECOND_BYTE_IN_SET 1

/** third byte in sets of 3 */
#define THIRD_BYTE_IN_SET 2

/** Saves all bits, clears two most significant */
#define MASK_FOR_BITS 0x3F

/**
 * Generates a 16-byte hash given a password and salt string.
 * 
 * @param pass password to hash
 * @param salt salt string used to hash the given password
 * @param result hash generated from MD5 hash algo
 */
void hashPassword( char const pass[], char const salt[ SALT_LENGTH + 1 ], char result[ PW_HASH_LIMIT + 1 ] );

#endif

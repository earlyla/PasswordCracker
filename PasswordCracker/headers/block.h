/**
 * @file block.c
 * @author Luke Early
 * Header file for block.c.
 */

#ifndef _BLOCK_H_
#define _BLOCK_H_

#include "magic.h"

/** A (partially filled) block of up to 64 bytes. */
typedef struct {
  // Array of bytes in this block. */
  byte data[ BLOCK_SIZE ];

  // Number of bytes in the data array currently in use.
  int len;
} Block;

/**
 * Dyanmically allocates memory for block and
 * initializes its fields.
 * 
 * @return pointer to the newly created block.
 */
Block *makeBlock();

/**
 * Frees the memory previously allocated to
 * the block passed as a parameter.
 * 
 * @param block pointer to the block who's memory
 *              is to be freed.
 */
void freeBlock( Block *block );

/**
 * Stores provided byte at the end of the provided block.
 * 
 * If adding the byte exceeds the block capacity, exit 
 * unsuccessfully.
 * 
 * @param block pointer to block where byte will be appended
 * @param b byte to append to block
 */
void appendByte( Block *block, byte b );

/**
 * Stores all bytes from given string in given block.
 * 
 * If block's capacity is exceeded, exit unsuccessfully.
 * 
 * @param block pointer to block to append src to
 * @param src string to append to block
 */
void appendString( Block *block, char const *src );

#endif

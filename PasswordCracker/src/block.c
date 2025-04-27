/**
 * @file block.c
 * @author Luke Early
 * Implements the block data structure. 
 * 
 * The block stores up to 64 bytes that can be 
 * used as input to the MD5 hash computation.
 */

#include "block.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

/**
 * Dyanmically allocates memory for block and
 * initializes its fields.
 * 
 * @return pointer to the newly created block.
 */
Block *makeBlock()
{
  Block *b1 = (Block *)malloc( sizeof( Block ) );

  b1->len = 0;

  return b1;
}

/**
 * Frees the memory previously allocated to
 * the block passed as a parameter.
 * 
 * @param block pointer to the block who's memory
 *              is to be freed.
 */
void freeBlock( Block *block )
{
  free( block );
}

/**
 * Stores provided byte at the end of the provided block.
 * 
 * If adding the byte exceeds the block capacity, exit 
 * unsuccessfully.
 * 
 * @param block pointer to block where byte will be appended
 * @param b byte to append to block
 */
void appendByte( Block *block, byte b )
{
  if ( ( block->len + 1 ) > BLOCK_SIZE ) {
    fprintf( stderr, "Block overflow\n" );
    exit( EXIT_FAILURE );
  } else {
    block->data[ block->len++ ] = b;
  }
}

/**
 * Stores all bytes from given string in given block.
 * 
 * If block's capacity is exceeded, exit unsuccessfully.
 * 
 * @param block pointer to block to append src to
 * @param src string to append to block
 */
void appendString( Block *block, char const *src )
{
  // byte length of src
  int numBytesToBeAdded = strlen( src );
  
  if ( ( block->len + numBytesToBeAdded ) > BLOCK_SIZE ) {
    fprintf( stderr, "Block overflow\n" );
    exit( EXIT_FAILURE );
  } else {
    for ( int i = 0; i < numBytesToBeAdded; i++ ) {
      block->data[ block->len++ ] = src[ i ];
    } 
  }
}

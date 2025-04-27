/**
 * @file password.c
 * @author Luke Early
 * Utilizes MD5 hash algo to implement password hashing
 */

#include "password.h"
#include "magic.h"
#include "md5.h"
#include <stdlib.h>
#include <string.h>

/** Number of iterations of hashing to make a password. */
#define PW_ITERATIONS 1000

/**
 * Computes the alternate hash for the given password.
 * 
 * Stores alternate hash in altHash array.
 * 
 * @param pass password to hash
 * @param salt salt string used to hash the given password
 * @param altHash array where the alternate hash is stored
 */
void computeAlternateHash( char const pass[], char const salt[ SALT_LENGTH + 1 ], byte altHash[ HASH_SIZE ] )
{
  /**
   * Init empty block
   */
  Block *altHashBlock = makeBlock();

  /**
   * Add password, salt, password again
   */
  appendString( altHashBlock, pass );
  appendString( altHashBlock, salt );
  appendString( altHashBlock, pass );

  /**
   * calculate alt hash
   */
  md5Hash( altHashBlock, altHash );
  free( altHashBlock );
  
}

/**
 * Computes the first intermediate hash from a given password, salt, 
 * and alternate hash.
 * 
 * Intermediate hash stored in intHash.
 * 
 * @param pass password to hash
 * @param salt salt string used to hash the given password 
 * @param altHash array where the alternate hash is stored
 * @param intHash 
 */
void computeFirstIntermediate( char const pass[], char const salt[ SALT_LENGTH + 1 ], byte altHash[ HASH_SIZE ], byte intHash[ HASH_SIZE ] )
{
  /**
   * Init empty block
   */
  Block *intHashBlock = makeBlock();

  int passwordLength = strlen( pass );

  /**
   * Add password, salt, password again
   */
  appendString( intHashBlock, pass );
  appendString( intHashBlock, "$1$" );
  appendString( intHashBlock, salt );

  /**
   * adds passwordLength bytes from altHash to end of intermediateHashBlock
   */
  for ( int i = 0; i < passwordLength; i++ ) {
    appendByte( intHashBlock, altHash[ i ] );
  }


  while ( passwordLength != 0 ) {
    int bit = passwordLength & 0x1;

    if ( bit == ZERO_BYTE_FLAG ) {
      intHashBlock->data[ intHashBlock->len++ ] = 0x00;
      passwordLength = passwordLength >> SINGLE_BIT_MOVEMENT;
    } else if ( bit == FIRST_BYTE_FLAG ) {
      intHashBlock->data[ intHashBlock->len++ ] = intHashBlock->data[ FIRST_BYTE_OF_BLOCK_DATA_IDX ];
      passwordLength = passwordLength >> SINGLE_BIT_MOVEMENT;
    }
  }

  md5Hash( intHashBlock, intHash );
  free( intHashBlock );
}

/**
 * Computes next intermediate hash given a password, salt string, and one of the
 * intermediate hashes.
 * 
 * @param pass password to hash
 * @param salt salt string used to hash the given password
 * @param inum iteration number parameter, between 0 and 999
 * @param intHash where intermediate hash is stored
 */
void computeNextIntermediate( char const pass[], char const salt[ SALT_LENGTH + 1 ], int inum, byte intHash[ HASH_SIZE ] )
{
  /**
   * Init empty block
   */
  Block *nextHashBlock = makeBlock();

  if ( inum % 2 == 0 ) { // i is even
    for ( int i = 0; i < HASH_SIZE; i++ ) {
      appendByte( nextHashBlock, intHash[ i ] );
    }
      if ( inum % 3 != 0 ) { // i not divisible by 3
      appendString( nextHashBlock, salt );
      }
      if ( inum % 7 != 0 ) { // i not divisible by 7
        appendString( nextHashBlock, pass );
      }
    appendString( nextHashBlock, pass );
  } else { // i is odd
    appendString( nextHashBlock, pass );

    if ( inum % 3 != 0 ) { // i not divisible by 3
      appendString( nextHashBlock, salt );
    }
    if ( inum % 7 != 0 ) { // i not divisible by 7
      appendString( nextHashBlock, pass );
    }
    for ( int i = 0; i < HASH_SIZE; i++ ) {
      appendByte( nextHashBlock, intHash[ i ] );
    }   
  }
  md5Hash( nextHashBlock, intHash );
  free( nextHashBlock );
}

/**
 * Converts a 16-byte hash to a string of printable characters from a given set.
 * 
 * Given set of characters:
 * ./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz
 * 
 * @param hash 16-byte hash to translate
 * @param result translation of 16-byte hash
 */
void hashToString( byte hash[ HASH_SIZE ], char result[ PW_HASH_LIMIT + 1 ] )
{
  byte hashRearr[ HASH_SIZE ];

  for ( int i = 0; i < HASH_SIZE; i++ ) {
    hashRearr[ i ] = hash[ pwPerm[ i ] ];
  }

  int resultCount = 0;

  for ( int i = 0; i < BYTE_TO_CHAR_TRANSLATION_ROUNDS; i++ ) {
    int byteSet = i * SET_OF_BYTES;
    byte letter1 = 0;
    byte letter2 = 0;
    byte letter3 = 0;
    byte letter4 = 0;

    if ( byteSet == 15 ) {
      // extract all the letters
      letter1 = hashRearr[ byteSet ];
      letter1 = letter1 & MASK_FOR_BITS;
      
      letter2 = hashRearr[ byteSet ] >> BITS_IN_LETTER;

      result[ resultCount++ ] = pwCode64[ letter1 ];
      result[ resultCount++ ] = pwCode64[ letter2 ];
    } else {
      // extract final letters
      letter1 = hashRearr[ byteSet ] & BITS_MASK_MSB;
      
      letter2 = hashRearr[ byteSet ] >> BITS_IN_LETTER;
      letter2 = ( hashRearr[ byteSet + SECOND_BYTE_IN_SET ] << LEFTOVER_BITS_LSB ) | letter2;
      letter2 = letter2 & BITS_MASK_MSB;

      letter3 = ( hashRearr[ byteSet + SECOND_BYTE_IN_SET ] >> LEFTOVER_BITS_MIDDLE ) | letter3;
      letter3 = ( hashRearr[ byteSet + THIRD_BYTE_IN_SET ] << LEFTOVER_BITS_MIDDLE ) | letter3;
      letter3 = letter3 & BITS_MASK_MSB;

      letter4 = hashRearr[ byteSet + THIRD_BYTE_IN_SET ] >> LEFTOVER_BITS_MSB;
      letter4 = letter4 & BITS_MASK_MSB;

      result[ resultCount++ ] = pwCode64[ letter1 ];
      result[ resultCount++ ] = pwCode64[ letter2 ];
      result[ resultCount++ ] = pwCode64[ letter3 ];
      result[ resultCount++ ] = pwCode64[ letter4 ];
    }
  }

  result[ resultCount ] = '\0';
}

/**
 * Generates a 16-byte hash given a password and salt string.
 * 
 * @param pass password to hash
 * @param salt salt string used to hash the given password
 * @param result hash generated from MD5 hash algo
 */
void hashPassword( char const pass[], char const salt[ SALT_LENGTH + 1 ], char result[ PW_HASH_LIMIT + 1 ] )
{
  // all hash arrays
  byte altHash[ HASH_SIZE ] = { 0 };
  byte intHash[ HASH_SIZE ] = { 0 };

  /**
   * Make a block, append pass to block
   */
  Block *b1 = makeBlock();
  appendString( b1, pass );

  /**
   * alternate hash
   */
  computeAlternateHash( pass, salt, altHash );
  
  /**
   * first intermediate hash
   */
  computeFirstIntermediate( pass, salt, altHash, intHash );

  for ( int i = 0; i < PW_ITERATIONS; i++ ) {
    computeNextIntermediate( pass, salt, i, intHash );
  }

  hashToString( intHash, result );
  free( b1 );
}

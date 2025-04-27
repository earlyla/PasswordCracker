/**
 * @file md5.c
 * @author Luke Early
 * Implements MD5 hash computation.
 */

#include "md5.h"
#include <stdlib.h>

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
word fVersion0( word B, word C, word D )
{
  word firstComparison = B & C;
  word secondComparison = ( ~B ) & D;

  return firstComparison | secondComparison;
}

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
word fVersion1( word B, word C, word D )
{
  word firstComparison = B & D;
  word secondComparison = C & ( ~D );

  return firstComparison | secondComparison;
}

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
word fVersion2( word B, word C, word D )
{
  return B ^ C ^ D;
}

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
word fVersion3( word B, word C, word D )
{
  word firstComaparison = B | ( ~D );
  return C ^ firstComaparison;
}

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
int gVersion0( int idx )
{
  return idx;
}

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
int gVersion1( int idx )
{
  return ( 5 * idx + 1 ) % 16;
}

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
int gVersion2( int idx )
{
  return ( 3 * idx + 5 ) % 16;
}

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
int gVersion3( int idx )
{
  return ( 7 * idx ) % 16;
}

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
word rotateLeft( word value, int s )
{
  // right shift to get the top s bits
  int getBitsNum = WORD_BIT_SIZE - s;
  word topSBits = value >> getBitsNum;
  value = value << s;
  word newValue = value | topSBits;

  return newValue;
}

/**
 * Array of fFunctions
 */
FFunction arrayF[ NUMBER_F_FXNS ] = { fVersion0, fVersion1, fVersion2, fVersion3 };

/**
 * Array of fFunctions
 */
GFunction arrayG[ NUMBER_G_FXNS ] = { gVersion0, gVersion1, gVersion2, gVersion3 };

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
void md5Iteration( word M[ BLOCK_WORDS ], word *A, word *B, word *C, word *D, int i )
{
  int roundNumber = i / SIZE_OF_ROUND;

  *A += (arrayF[ roundNumber ])( *B, *C, *D );
  *A += M[ (arrayG[ roundNumber ])( i ) ];
  *A += md5Noise[ i ];
  *A = rotateLeft( *A, md5Shift[ i ] );
  *A += *B;

  word tempA = *A;
  word tempB = *B;
  word tempC = *C;

  *A = *D;
  *B = tempA;
  *C = tempB;
  *D = tempC;
}

/**
 * Pads block to increase it's length to 64 bytes.
 * 
 * @param block the block which will be padded
 */
void padBlock( Block *block )
{
  unsigned long lenBytes = block->len * BITS_IN_A_BYTE;

  // add 0x80, then pad with 0x00 until 56
  appendByte( block, FIRST_VALUE_AFTER_DATA );
  while ( block->len < BLOCK_ZERO_PADDING_LIMIT ) {
    appendByte( block, BLOCK_DATA_PADDING );
  }

  for( int i = 0; i < BITS_IN_A_BYTE; i++ ) {
    byte lsb = ( lenBytes >> ( BITS_IN_A_BYTE * i ) ) & 0x00000000000000FF;
    appendByte( block, lsb );
  }
}

/**
 * Pads given input block, computes the MD5 hash with helper functions, 
 * stores the results in a given hash array.
 * 
 * @param block block of data
 * @param hash list of hashes
 */
void md5Hash( Block *block, byte hash[ HASH_SIZE ] )
{
  /** 
   * Starting values for words A, B, C, D 
   */
  word A = INIT_VALUE_A;
  word B = INIT_VALUE_B;
  word C = INIT_VALUE_C;
  word D = INIT_VALUE_D;

  /** 
   * List of words
   */
  word M[ HASH_SIZE ];

  /** 
   * Ensure block is properly padded
   */
  padBlock( block );

  /**
   * Fill M with 16 words
   */
  for ( int i = 0; i < HASH_SIZE; i++ ) {
    word w = 0;
    int leastSigByte = i * NUMBER_OF_BYTES_IN_WORD;
    int mostSigByte = ( leastSigByte + NUMBER_OF_BYTES_IN_WORD ) - 1;

    for ( int j = mostSigByte; j > leastSigByte - 1; j-- ) {
      if ( j == leastSigByte ) {
        w = w | block->data[ j ];
      } else {
        w = w | block->data[ j ];
        w = w << BITS_IN_A_BYTE;
      }
    }
    M[ i ] = w;
  }

  /**
   * Complete 64 iterations of md5 algorithm
   */
  for ( int i = 0; i < BLOCK_SIZE; i++ ) {
    md5Iteration( M, &A, &B, &C, &D, i );
  }

  /**
   * Add back in the initialization values
   */
  A += INIT_VALUE_A;
  B += INIT_VALUE_B;
  C += INIT_VALUE_C;
  D += INIT_VALUE_D;

  for ( int i = 0; i < HASH_SIZE; i++ ) {
    byte byteToLoad = 0;
    if ( i >= WORD_A_FIRST_BYTE && i < WORD_A_LAST_BYTE ) {
      byteToLoad = byteToLoad | A;
      hash[ i ] = byteToLoad;
      A = A >> BITS_IN_A_BYTE;
    } else if ( i >= WORD_B_FIRST_BYTE && i < WORD_B_LAST_BYTE ) {
      byteToLoad = byteToLoad | B;
      hash[ i ] = byteToLoad;
      B = B >> BITS_IN_A_BYTE;
    } else if ( i >= WORD_C_FIRST_BYTE && i < WORD_C_LAST_BYTE ) {
      byteToLoad = byteToLoad | C;
      hash[ i ] = byteToLoad;
      C = C >> BITS_IN_A_BYTE;
    } else {
      byteToLoad = byteToLoad | D;
      hash[ i ] = byteToLoad;
      D = D >> BITS_IN_A_BYTE;
    } 
  }
}

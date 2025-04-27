/**
 * @file crack.c
 * @author Luke Early
 * Main component for the program.
 */

#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <ctype.h>

#include "password.h"

/** Maximum username length */
#define USERNAME_LIMIT 32

/** Maximum number of words we can have in the dictionary. */
#define DLIST_LIMIT 1000

/** Number of required arguments on the command line. */
#define REQ_ARGS 2

/** initial capacity of a resizable string */
#define INIT_STR_CAP 5

/** initial capacity of a resizable array */
#define INIT_ARR_CAP 5

/** number of excess shadow file characters */
#define EXCESS_SHADOW 18

/** length of the MD5 ID */
#define MD5_ID_HASH_LENGTH 3

/** max number of command line arguments */
#define MAX_NUMBER_CLA 3

/** location of dictionary file name in argv array */
#define DICTIONARY_FILE_NAME_LOCATION 1

/** location of shadow file name in argv array */
#define SHADOW_FILE_NAME_LOCATION 2

/** factor by which to resize things that are resizeable */
#define RESIZE_FACTOR 2

/** standard length of dict file name: dictionary-00.txt */
#define STANDARD_DICT_FILE_LEN 17

/** standard length of shad file name: shadow-00.txt */
#define STANDARD_SHAD_FILE_LEN 13

/**
 * Struct for users
 */
struct UserStruct {
  char userName[ USERNAME_LIMIT + 1 ];
  char userHash[ PW_HASH_LIMIT + 1 ];
  char userSalt[ SALT_LENGTH + 1 ];
  struct UserStruct *next;
};

/** type name for user struct */
typedef struct UserStruct User;

/** Type for representing a word in the dictionary. */
typedef char Password[ PW_LIMIT + 1 ];

/** Print out a usage message and exit unsuccessfully. */
static void usage()
{
  fprintf( stderr, "Usage: crack dictionary-filename shadow-filename\n" );
  exit( EXIT_FAILURE );
}

/**
 * Reads in a single line of input from dictionary file stream.
 * 
 * Stores it in str param.
 * 
 * @param fp pointer to input stream
 * @param str string to store it in
 */
void readDictLine( FILE *fp, char *str )
{
  int count = 0;
  int capacity = INIT_STR_CAP;
  char *dictStr = malloc( INIT_STR_CAP * sizeof( char ) );
  
  char currChar;
  
  while ( fscanf( fp, "%c", &currChar ) == 1 ) {
    if ( isspace( currChar ) && currChar != '\n' ) {
      fprintf( stderr, "Invalid dictionary word\n" );
      exit( EXIT_FAILURE );
    }

    if ( isspace( currChar ) && currChar == '\n' ) {
      break;
    }

    // resize string array if exceeds capacity
    if ( count + 1 >= capacity ) {
      capacity *= RESIZE_FACTOR;
      dictStr = realloc( dictStr, capacity*sizeof( char ) );
    } 

    dictStr[ count ] = currChar;
    count++;
  }

  if ( feof( fp ) ) {
    dictStr = NULL;
    count = 0;
  }

  if ( count > 0 ) {
    dictStr[ count ] = '\0';
  }

  if ( count > PW_LIMIT ) {
    fprintf( stderr, "Invalid dictionary word\n" );
    exit( EXIT_FAILURE );
  }

  if ( dictStr == NULL ) {
    strcpy( str, "" );
    free( dictStr );
  } else {
    strcpy( str, dictStr );
    free( dictStr );
  }
}

/**
 * Reads in a single line of input from shadow file.
 * 
 * Adds User to the end of the linked list, returns the new head pointer.
 * 
 * @param fp pointer to input stream
 * @param head current head pointer for linked list of Users
 * @return new head pointer
 */
User * readUserFromFile( User *head, FILE *fp )
{
  char nameStr[ USERNAME_LIMIT + 1 ] = "";
  char saltStr[ SALT_LENGTH + 1 ] = "";
  char hashStr[ PW_HASH_LIMIT + 1 ] = ""; 
  char trash[ EXCESS_SHADOW + 1 ] = "";
  char md5IdHash[ MD5_ID_HASH_LENGTH + 1 ] = "";

  User *newUser = (User *)calloc( 1, sizeof( User ) );

  if ( fscanf( fp, "%[a-zA-Z]:", nameStr ) == 1 ) {
    nameStr[ strlen( nameStr ) ] = '\0';
    strncpy( newUser->userName, nameStr, USERNAME_LIMIT );
  }

  if ( fscanf( fp, "%3c", md5IdHash ) == 1 ) {
    if ( strncmp( md5IdHash, "$1$", MD5_ID_HASH_LENGTH ) != 0 ) {
      fprintf( stderr, "Invalid shadow file entry\n" );
      exit( EXIT_FAILURE );
    }
  }

  if ( fscanf( fp, "%[a-zA-Z0-9./]$", saltStr ) == 1 ) {
    if ( strlen( saltStr ) > SALT_LENGTH ) {
      fprintf( stderr, "Invalid shadow file entry\n" );
      exit( EXIT_FAILURE );
    }
    strncpy( newUser->userSalt, saltStr, SALT_LENGTH );
  }

  if ( fscanf( fp, "%[a-zA-z0-9./]:", hashStr ) == 1 ) {
    fscanf( fp, "%18c\n", trash );
    hashStr[ strlen( hashStr ) ] = '\0';
    strncpy( newUser->userHash, hashStr, PW_HASH_LIMIT );
  }

  if ( head == NULL ) {
    return newUser;
  }

  User * temp = head;

  while ( temp->next != NULL ) {
    temp = temp->next;
  }

  temp->next = newUser;
  return head;
}


/**
 * Driver function for the program.
 */
int main( int argc, char *argv[] )
{
  /**
   * Check for valid file names
   * 
   * If valid store, else usage() 
   */
  char *testStr;
  if ( argc != MAX_NUMBER_CLA ) {
    usage();
  } 
  
  testStr = strstr( argv[ DICTIONARY_FILE_NAME_LOCATION ], "dictionary" );
  if ( testStr == NULL ) {
    usage();
  }

  testStr = strstr( argv[ SHADOW_FILE_NAME_LOCATION ], "shadow" );
  if ( testStr == NULL ) {
    usage();
  }

  /**
   * Ensure files open
   */
  FILE *dictFilePtr = fopen( argv[ DICTIONARY_FILE_NAME_LOCATION ], "r" );
  FILE *shadowFilePtr = fopen( argv[ SHADOW_FILE_NAME_LOCATION ], "r" );

  if ( dictFilePtr == NULL ) {
    perror( argv[ DICTIONARY_FILE_NAME_LOCATION ] );
    exit( EXIT_FAILURE );
  } else if ( shadowFilePtr == NULL ) {
    perror( argv[ SHADOW_FILE_NAME_LOCATION ] );
    exit( EXIT_FAILURE );
  }

  /**
   * Read in the dictionary
   */
  char **dictArray = (char **)malloc( INIT_ARR_CAP * sizeof( Password ) );
  int dictArraySize = 0;
  int dictArrayCap = INIT_ARR_CAP;

  char *dictLine = (char *)malloc( PW_LIMIT * sizeof( char ) );
  readDictLine( dictFilePtr, dictLine );

  while ( ( strcmp( dictLine, "" ) != 0 ) ) {
    /**
     * resize array if need be
     */
    if ( dictArraySize + 1 >= dictArrayCap ) {
      dictArrayCap *= RESIZE_FACTOR;
      dictArray = (char **)realloc( dictArray, dictArrayCap * sizeof( Password ) );
    }

    /**
     * 1. add next word to dictionary array
     * 
     * 2. Read in next line
     */
    dictArray[ dictArraySize++ ] = dictLine;
    if ( dictArraySize > DLIST_LIMIT ) {
      fprintf( stderr, "Too many dictionary words\n" );
      exit( EXIT_FAILURE );
    }
    
    dictLine = (char *)malloc( PW_LIMIT * sizeof( char ) );
    readDictLine( dictFilePtr, dictLine );
  }

  User *list = NULL;
  int userCount = 0;
  
  while ( true ) {
    if ( feof( shadowFilePtr ) ) {
      break;
    }
    
    list = readUserFromFile( list, shadowFilePtr );
    userCount++;
  }

  /**
   * Check passwords
   */
  for ( User *curr = list; curr; curr = curr->next ) {
    char hashResult[ PW_HASH_LIMIT + 1 ] = "";

    for ( int j = 0; j < dictArraySize; j++ ) {
      hashPassword( dictArray[ j ], curr->userSalt, hashResult );
      if ( strcmp( hashResult, curr->userHash ) == 0 ) {
        printf( "%s : %s\n", curr->userName, dictArray[ j ] );
      }
    }
  }

  /**
   * free all heap mem and close all file streams
   */
  for ( int i = 0; i < dictArraySize; i++ ) {
    free( dictArray[ i ] );
  }

  for ( User *curr = list; curr; ) {
    User *temp = curr->next;
    free( curr );
    curr = temp;
  }

  free( dictLine );
  free( dictArray );
  fclose( dictFilePtr );
  fclose( shadowFilePtr );

}

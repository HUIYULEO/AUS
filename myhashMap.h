#ifndef MYHASHMAP_H
#define MYHASHMAP_H

#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define BUCKETCOUNT 16

//hashnode struct
typedef struct hashEntry{
    char* key;
    char* value;
    struct hashEntry* next;
}entry;

//typedef struct hashEntry entry;
typedef struct hashTable{
     entry bucket[BUCKETCOUNT];  //16 bucketcount
}table;

void initHashTable(table* table);
void freeHashTable(table* table);
int keyToIndex(const char* key);
char* strDup(const char* str);
int insertEntry(table* table , const char* key , const char* value);
const char* findValueByKey(const table* table , const char* key);
entry* removeEntry(table* table , char* key);
void printTable(table* table);

#endif //_HASHMAP_H

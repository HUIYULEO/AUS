
#include "messages.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>

#define BACKLOG 10 // Number of pending connections allowed
#define HASHSIZE 16

struct request_packet {
    uint8_t hash[SHA256_DIGEST_LENGTH];
    uint64_t start, end;
    uint8_t p;
};

//hashnode struct
typedef struct hashNode {
    uint8_t key;
    char* value;
    struct hashNode* next;
}node;

//hashTable struct
typedef struct hashTable {
    node hashsize[HASHSIZE];
}table;

void initHashTable(table* t) {
    int i;
    if (t == NULL) return;
    for (i = 0;i < HASHSIZE; ++i) {
        t->hashsize[i].key = 0;
        t->hashsize[i].value = NULL;
        t->hashsize[i].next = NULL;
    }
}

void freeHashTable(table* t) {
    int i;
    node* e,*ep;
    if (t == NULL)return;
    for (i = 0; i < HASHSIZE; ++i){
        e = &(t -> hashsize[i]);
        while(e -> next != NULL) {
            ep = e->next;
            e->next = ep->next;
            //free(ep-> key);
            free(ep->value);
            free(ep);
        }
    }
}

//HashMap algorithem 
int keyToIndex(const uint8_t key){
    int index, len, i;
    if (key == 0)return -1;

    // len = strlen(key);
    index = (int)key/(HASHSIZE);
    // for (i = 1; i<len; ++i) {
    //     index *= 1103515245 + (int)key[i];
    // }
    // index >>= 27;
    // index &= (HASHSIZE-1);
    return index;
}

//insert hashnode data
int insertNode(table* t , const uint8_t key , const char* value)
{
    int index , vlen1 , vlen2;
    node* e , *ep;

    if (t == NULL || key == 0 || value == NULL) {
        return -1;
    }

    index = keyToIndex(key);
    if (t->hashsize[index].key == 0) {
        t->hashsize[index].key = key;
        t->hashsize[index].value = strdup(value); 
    }
    else {
        e = ep = &(t->hashsize[index]);
        while (e != NULL) { 
            if (memcmp(&(e->key) , &key, SHA256_DIGEST_LENGTH) == 0) {
                vlen1 = strlen(value);
                vlen2 = strlen(e->value);
                if (vlen1 > vlen2) {
                    free(e->value);
                    e->value = (char*)malloc(vlen1 + 1);
                }
                memcpy(e->value , value , vlen1 + 1);
                return index;   
            }
            ep = e;
            e = e->next;
        } 
        //make new one
        e = (node*)malloc(sizeof (node));
        e->key = key;
        e->value = strdup(value);
        e->next = NULL;
        ep->next = e;
    }
    return index;
}

//find value from hashtable by key
//if true return value address，false return NULL
const char* findValueByKey(const table* t , const uint8_t key)
{
    int index;
    const node* e;
    if (t == NULL || key == 0) {
        return NULL;
    }
    index = keyToIndex(key);
    printf("%d",index);
    e = &(t->hashsize[index]);
    if (e->key == 0) return NULL;//empty 
    while (e != NULL) {
        // if (0 == strcmp(key , e->key)) {
        //     return e -> value;    
        // }
        if(memcmp(&key, &(e->key), SHA256_DIGEST_LENGTH) == 0){
            return e->value;
        }
        e = e->next;
    }
    return NULL;
}

void printTable(table* t)
{
    int i;
    node* e;
    if (t == NULL)return;
    for (i = 0; i<HASHSIZE; ++i) {
        printf("\nhashsize[%d]:\n" , i);
        e = &(t->hashsize[i]);
        while (e->key != 0) {
            printf("\t%d\t=\t%s\n" , e->key , e->value);
            if (e->next == NULL)break;
            e = e->next;
        }
    }
}


void generate_hash(uint8_t *buffer, uint64_t *number, int length) {
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, number, length);
    SHA256_Final(buffer, &sha256);
}

uint64_t generate_answer(uint8_t hash[SHA256_DIGEST_LENGTH], uint64_t start, uint64_t end, table t) {
    uint8_t buffer[SHA256_DIGEST_LENGTH];
    uint8_t key[SHA256_DIGEST_LENGTH];
    uint64_t answer;
    uint64_t guess = start;

    //printf(hash);
   // printf(pipe(hash[SHA256_DIGEST_LENGTH]))
    printf("hashcode:%d\n",hash[1]);
    insertNode(&t, hash[1], "1" );
    //printTable(&t);
    while (guess < end) {
        generate_hash(buffer, &guess, sizeof(guess)); // generate the SHA-256 hash for the current guess

        if (memcmp(hash, buffer, SHA256_DIGEST_LENGTH) == 0) { // check if we have a match
            answer = guess;
            return answer;
        } else {
            memset(buffer, 0, SHA256_DIGEST_LENGTH);
            guess++;
        }
    }

    return -1; // error guessing hash
}


void unpack_request_packet(const char *packet, struct request_packet *request) {

    for (int i = PACKET_REQUEST_HASH_OFFSET; i < PACKET_REQUEST_START_OFFSET; ++i) {
        request->hash[i] = packet[i];
        printf("%d=%d\n", i,request->hash[i]);
    }

    for (int i = PACKET_REQUEST_START_OFFSET; i < PACKET_REQUEST_END_OFFSET; ++i) {
        request->start <<= 8;
        request->start |= (uint8_t) packet[i];
    }

    for (int i = PACKET_REQUEST_END_OFFSET; i < PACKET_REQUEST_PRIO_OFFSET; ++i) {
        request->end <<= 8;
        request->end |= (uint8_t) packet[i];
    }

    request->p = packet[PACKET_REQUEST_PRIO_OFFSET];
}


void handle_packet(int sock,table t) {
    struct request_packet request;
    char packet[PACKET_REQUEST_SIZE];
    memset(packet, 0, PACKET_REQUEST_SIZE);

    if (recv(sock, packet, sizeof(packet), 0) == -1) {
        perror("receiving");
        exit(EXIT_FAILURE);
    } else {
        printf("Packet \n");
    }

    unpack_request_packet(packet, &request);

    uint64_t answer = htobe64(generate_answer(request.hash, request.start, request.end, t));
    if (answer == -1) {
        printf("Error guessing hash\n");
    }

    if (send(sock, &answer, PACKET_RESPONSE_SIZE, 0) == -1) {
        perror("sending");
        exit(EXIT_FAILURE);
    } else {
        printf("Answer sent successfully!\n");
    }
}


/* Simple TCP server based on tutorial from
 * https://www.tutorialspoint.com/unix_sockets/socket_quick_guide.htm
 */
int main(int argc, char **argv) {
    int sockfd, newsockfd, portno, clilen;
    struct sockaddr_in serv_addr, cli_addr;
    int pid;

    if (argc != 2) {
        printf("usage: %s port", *argv);
        exit(EXIT_FAILURE);
    }

    portno = atoi(*(argv + 1));

    if (portno < 1024 || portno > 65535) {
        printf("Invalid port");
        exit(EXIT_FAILURE);
    } else {
        printf("Port: %d\n", portno);
    }


    /* A call to socket to define communication protocol.
     * AF_INET      : IPv4 protocol
     * SOCK_STREAM  : Stream socket (for TCP connection)
     * 0            : Use system default protocol.
     * Returns a socket descriptor.
     */
    sockfd = socket(AF_INET, SOCK_STREAM, 0);

    if (sockfd == -1) {
        perror("Failed to create socket\n");
        exit(EXIT_FAILURE);
    } else {
        printf("Socket was created successfully\n");
    }

    memset(&serv_addr, 0, sizeof(serv_addr));

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = INADDR_ANY;
    serv_addr.sin_port = htons(portno);

    if (bind(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0) {
        perror("binding");
        exit(EXIT_FAILURE);
    } else {
        printf("Binding was successful\n");
    }

    // begin listening for incoming connections
    if (listen(sockfd, BACKLOG) == -1) {
        printf("listen");
        exit(EXIT_FAILURE);
    } else {
        printf("Server is listening!\n");
    }

    clilen = sizeof(cli_addr);

    //test
    table t;
    initHashTable(&t);
    insertNode(&t , (uint8_t)44445 , "1" );
    const uint8_t key1 = (uint8_t)44445 ;
    const char* value = findValueByKey(&t , key1);

    if(value != NULL){
        printf("find %d\t=\t%s\n", key1,value);
    }else{
        printf("not found");
    }

    while (1) { // loop for accepting incoming connections
        newsockfd = accept(sockfd, (struct sockaddr *) &cli_addr, &clilen);

        if (newsockfd == -1) {
            printf("Error during accept");
            exit(EXIT_FAILURE);
        } else {
            printf("Accept was successful\n");
        }

        pid = fork();

        if (pid < 0) {
            perror("Error on fork");
            exit(EXIT_FAILURE);
        }

        if (pid == 0) { // this is the child process
            close(sockfd);
            //insertNode(&t , hashcode , "1" );
            printTable(&t);
            handle_packet(newsockfd,t);
            exit(EXIT_SUCCESS);
        }
        close(newsockfd);
    }

    return 0;
}

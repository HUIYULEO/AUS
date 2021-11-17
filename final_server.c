
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
    uint8_t key[SHA256_DIGEST_LENGTH];
    uint64_t value;
    struct hashNode* next;
}node;

//hashTable struct
typedef struct hashTable {
    node hashsize[HASHSIZE];
}table;

void initHashTable(table* t) {
    int i;
    uint8_t zero[SHA256_DIGEST_LENGTH];
    memset(zero, 0, SHA256_DIGEST_LENGTH);
    if (t == NULL) return ;
    for (i = 0;i < HASHSIZE; ++i) {
        for (int j = 0; j < SHA256_DIGEST_LENGTH; j++)
        {
            t->hashsize[i].key[j] = zero[j];
        }
        t->hashsize[i].value = 0;
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
            //free(ep->value);
            free(ep);
        }
    }
}

//HashMap algorithem 
int keyToIndex(const uint8_t key[SHA256_DIGEST_LENGTH]){
    int index, len, i;
    uint8_t zero[SHA256_DIGEST_LENGTH];
    memset(zero, 0, SHA256_DIGEST_LENGTH);
    if (memcmp(key, zero, SHA256_DIGEST_LENGTH) == 0)return -1;
    index = ((int)key[1]+13)%(HASHSIZE);
    printf("index:%d\n",index);
    return index;
}

//insert hashnode data
int insertNode(table* t , const uint8_t key[SHA256_DIGEST_LENGTH] , const uint64_t value)
{
    int index , vlen1 , vlen2;
    node* e , *ep;
    uint8_t zero[SHA256_DIGEST_LENGTH];
    memset(zero, 0, SHA256_DIGEST_LENGTH);

    if (t == NULL || memcmp(key, zero, SHA256_DIGEST_LENGTH) == 0 || value == 0) {
        return -1;
    }

    index = keyToIndex(key);
    e = ep = &(t->hashsize[index]);
    e = (node*)malloc(sizeof (node));
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
    {
        (e->key)[i] = key[i];
    }
    e->value = value;
    e->next = NULL;
    ep->next = e;
    printf("insert new key\n");
    return index;
}

//find value from hashtable by key
//if true return value address，false return NULL
const uint64_t findValueByKey(const table* t , const uint8_t key[SHA256_DIGEST_LENGTH])
{
    int index;
    const node* e;
    uint8_t zero[SHA256_DIGEST_LENGTH];
    memset(zero, 0, SHA256_DIGEST_LENGTH);
    if (t == NULL || memcmp(key, zero, SHA256_DIGEST_LENGTH) == 0) {
        return 0;
    }
    index = keyToIndex(key);
    //printf("%d",index);
    e = &(t->hashsize[index]);
    while (e != NULL) {
        if(memcmp(key, e->key, SHA256_DIGEST_LENGTH) == 0){
            printf("find the value\n");
            return e->value;
        }
        e = e->next;
    }
    return 0;
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
            for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
            {
                printf("\t%d" , (e->key)[i]);
            }
            printf("\t=%lu\n", e->value);
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

uint64_t generate_answer(uint8_t hash[SHA256_DIGEST_LENGTH], uint64_t start, uint64_t end, table* t) {
    uint8_t buffer[SHA256_DIGEST_LENGTH];
    uint64_t answer;
    uint64_t guess = start;

    const uint64_t value = findValueByKey(t, hash);
    if(value != 0){
        printf("repeat hash:%d\t=\t%lu\n", hash[1], value);
        return value;
    }else{
        printf("not found\n");
    }
    while (guess < end) {
        generate_hash(buffer, &guess, sizeof(guess)); // generate the SHA-256 hash for the current guess
        if (memcmp(hash, buffer, SHA256_DIGEST_LENGTH) == 0) { // check if we have a match
            answer = guess;
            insertNode(t, hash, answer);
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
        printf("%d", request->hash[i]);
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


void handle_packet(int sock,table* t) {
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
    //insertNode(t, request.hash , (uint64_t)15);
    //printf("table_later");
    //printTable(t);

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

    //test
    table t;
    initHashTable(&t);
    //printTable(&t);

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

    while (1) { // loop for accepting incoming connections
        newsockfd = accept(sockfd, (struct sockaddr *) &cli_addr, &clilen);

        if (newsockfd == -1) {
            printf("Error during accept");
            exit(EXIT_FAILURE);
        } else {
            printf("Accept was successful\n");
        }

        handle_packet(newsockfd,&t);
        //printTable(&t);
        // pid = fork();

        // if (pid < 0) {
        //     perror("Error on fork");
        //     exit(EXIT_FAILURE);
        // }

        // if (pid == 0) { // this is the child process
        //     close(sockfd);
        //     handle_packet(newsockfd,&t);
        //     exit(EXIT_SUCCESS);
        // }
        close(newsockfd);
    }
    freeHashTable(&t);
    return 0;
}

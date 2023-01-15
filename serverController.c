#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <linux/tcp.h>
#include <fcntl.h>
#include <openssl/sha.h>
#include <sys/time.h> 
#include <stdint.h> 
#include <errno.h> 

#define TARGETTOFUZZ      "/home/ubuntu/exif/exif"
// #define TARGETTOFUZZ   "exiv2"
// #define TARGETTOFUZZ   "pdfimages"

#define REQUEST_MAX_SIZE  32 
#define RESPONSE_MAX_SIZE 32 
#define BUFLEN            4096

extern char* get_bytes(char*, int*);

char *requests[] = {
	"#1#GET MY INITIAL TESTCASE#####",
	"#2#VERIFY THIS BACKTRACE#######",
};

char *responses[] = {
	"#1#BACKTRACE ALREADY REGISTERED",
	"#2#THAT'S NEW! GIVE IT TO ME###",
};

typedef struct CRASHFUL_ITEM {
    int  id;
    int  filelen;
    int  crash_line;
    char *fileData;
    unsigned char backtrace_SHA256_hash[SHA256_DIGEST_LENGTH];
    unsigned char crash_type[256];
    unsigned char crash_function[256];
    struct CRASHFUL_ITEM *next;
} TYPE_CRASHFUL_ITEM;

struct CRASHFUL_ITEM *global_backtraces_list = NULL;
extern int global_fd_socket;
int total_crashes=0;
/* ************************************************************************** */

int verifyBacktraceAlreadyExist(unsigned char *backtraceHash, unsigned char *data, int filelen, int crash_line, unsigned char *crash_type, unsigned char *crash_function) {

    struct CRASHFUL_ITEM *current = global_backtraces_list;

    // // Registra o primeiro backtrace
    if(!global_backtraces_list) {
        global_backtraces_list             = malloc(sizeof(TYPE_CRASHFUL_ITEM));
        global_backtraces_list->id         = total_crashes;
        global_backtraces_list->crash_line = crash_line;
        strcpy(global_backtraces_list->crash_type, crash_type);
        strcpy(global_backtraces_list->crash_function, crash_function);
        global_backtraces_list->fileData = malloc(filelen);
        memcpy(global_backtraces_list->fileData,data,filelen);
        memcpy(global_backtraces_list->backtrace_SHA256_hash, backtraceHash, SHA256_DIGEST_LENGTH);
        global_backtraces_list->filelen  = filelen;
        global_backtraces_list->next     = NULL;

        // Envia o backtrace para analise do servidor 
        // __sendBacktraceHashToAnalysis(backtraceHash, mutatedFile, filelen);
        
        total_crashes++;
        return 0; // Hash ainda nao foi registrado
    }

    while(current != NULL) {
        if(memcmp(current->backtrace_SHA256_hash, backtraceHash, SHA256_DIGEST_LENGTH)==0) {
            return 1; // Hash ja foi registrado
        }   
        else
            current=current->next;            
    }

    current            = malloc(sizeof(TYPE_CRASHFUL_ITEM));
    current->id        = total_crashes;
    current->crash_line = crash_line;
    strcpy(current->crash_type, crash_type);
    strcpy(current->crash_function, crash_function);
    current->fileData = malloc(filelen);
    memcpy(current->fileData,data,filelen);
    memcpy(current->backtrace_SHA256_hash, backtraceHash, SHA256_DIGEST_LENGTH);
    current->filelen  = filelen;
    current->next     = NULL;

    total_crashes++;
    return 0; // Hash ainda nao foi registrado
}

int getChildBacktraceAndVerifyHashExist(char *libSegFaultStackTraceFileName, char *mutatedFile, int filelen, int counter) 
{
    unsigned char *data, *backtrace, crashType[256]={0}, crashLineAddr[256]={0}, crashFunctionName[256]={0}, *pfound1, *pfound2, *backtraceHash, shellInput[256]={0}, shellOutput[256] = {0};
    char *token;
    int bytes_send, backtraceSize, crashTypeSize, crashLineAddrSize, crashFunctionNameSize, crashLineAddrVal;
    FILE *fp;

    data = get_bytes(libSegFaultStackTraceFileName, NULL);

    pfound1       = strstr(data, "***"); 
    pfound2       = strstr(data, "Register dump:"); 
    crashTypeSize = pfound2-pfound1-1;
    memcpy(crashType,pfound1,crashTypeSize);

    pfound1       = strstr(data, "Backtrace:"); 
    pfound2       = strstr(data, "Memory map:"); 
    backtraceSize = pfound2-pfound1-2;
    backtrace     = malloc(backtraceSize);
    memcpy(backtrace,pfound1,backtraceSize);

    pfound1       = strstr(data, "(+0x"); 
    pfound2       = strstr(data, ")["); 
    crashLineAddrSize = pfound2-pfound1;
    memcpy(crashLineAddr,pfound1+2,crashLineAddrSize-2);

    sprintf(shellInput,"addr2line -e %s -f -C %s",TARGETTOFUZZ,crashLineAddr);
    fp = popen(shellInput, "r");
    if (fp == NULL) {
        printf("Failed to run command\n" );
        exit(1);
    }
    /* Read the output a line at a time - output it. */
    int line=0;
    while (fgets(shellOutput, BUFLEN, fp) != NULL){
        // Pega o nome da funcao 
        if(line==0) {
            strcpy(crashFunctionName,shellOutput);
            memset(shellOutput,0,256);
            line=1;
        }
        // Pega o numero da linha
        else {
            pfound1 = strstr(shellOutput, ":"); 
            pfound2 = strstr(shellOutput, "\n"); 
            crashLineAddrSize = pfound2-pfound1;
            memset(crashLineAddr,0,256);
            memcpy(crashLineAddr,pfound1+1,crashLineAddrSize-1);
            crashLineAddrVal = atoi(crashLineAddr);
        }
    };
    pclose(fp);

    backtraceHash = SHA256(backtrace, backtraceSize, NULL);
    // printf("SHA256: ");
    // for (int i = 0; i < 32; i++) {
    //     printf("%02x", hash[i]);
    // }

    // Backtrace ja registrado
    if(verifyBacktraceAlreadyExist(backtraceHash, mutatedFile, filelen, crashLineAddrVal, crashType, crashFunctionName)) {
        return 1;
    }
    // Backtrace ainda nao registrado
    else {
        // Envia o backtrace para analise do servidor 
        // __sendBacktraceHashToAnalysis(backtraceHash, mutatedFile, filelen);
        return 0;
    }
}   

int __fuzzServerConnectAndGetTestcase(char* addr, unsigned int port, unsigned char* testcase) {
    struct sockaddr_in server;
    unsigned char buf_rx[RESPONSE_MAX_SIZE],buf_tx[REQUEST_MAX_SIZE];
    int len,flags,bytes_read,bytes_send;

    //Create socket
    global_fd_socket = socket(AF_INET , SOCK_STREAM, 0);
    if (global_fd_socket == -1) {
        perror("Could not create socket. Error");
        return 1;
    }

    server.sin_addr.s_addr = inet_addr(addr);
    server.sin_family      = AF_INET;
    server.sin_port        = htons(port);

    // Connect to remote server
    if (connect(global_fd_socket, (struct sockaddr *)&server , sizeof(server)) < 0) {
        perror("connect failed. Error");
        return -1;
    }
    puts("Connected...\n");

    // Set socket to non-blocking mode (very important!)
    flags = fcntl(global_fd_socket, F_SETFL, flags | O_NONBLOCK);

    // Requisita o testcase inicial 
    memcpy(buf_tx, requests[0], REQUEST_MAX_SIZE);
    if ((bytes_send = send(global_fd_socket, buf_tx, REQUEST_MAX_SIZE, 0)) < 0) {
        perror("Error sending buf data");
        return 1;
    }

    return global_fd_socket;
}

int __sendBacktraceHashToAnalysis(unsigned char *hash, unsigned char *fileData, int filelen) {
    
    int flags,bytes_read,bytes_send;
    unsigned char buf_rx[RESPONSE_MAX_SIZE], buf_tx[REQUEST_MAX_SIZE];    
    /* wait for something to happen on the socket */
    struct timeval ts;
    ts.tv_sec  = 1; /* timeout (secs.) */
    ts.tv_usec = 0; /* 0 microseconds */	
    fd_set fds;
    
    flags = fcntl(global_fd_socket, F_SETFL, flags | O_NONBLOCK);
    memcpy(buf_tx,requests[1],REQUEST_MAX_SIZE);
    if ((bytes_send = send(global_fd_socket, buf_tx, REQUEST_MAX_SIZE, 0)) < 0) {
        perror("Error sending buf data");
        return 1;
    }

    // sleep(1);
    flags = fcntl(global_fd_socket, F_SETFL, flags | O_NONBLOCK);
    memcpy(buf_tx,hash,SHA256_DIGEST_LENGTH);
    if ((bytes_send = send(global_fd_socket, buf_tx, SHA256_DIGEST_LENGTH, 0)) < 0) {
        perror("Error sending buf data");
        return 1;
    }

    while (1) {
        FD_ZERO(&fds);
        if (global_fd_socket != 0)
            FD_SET(global_fd_socket, &fds);

        int nready = select(global_fd_socket + 1, &fds, NULL, NULL, &ts);
        if (nready < 0) {
            perror("select. Error");
            return 1;
        }
        else if (nready == 0) {
            ts.tv_sec = 1; // 1 second
            ts.tv_usec = 0;
        }
        else if (global_fd_socket != 0 && FD_ISSET(global_fd_socket, &fds)) {
            
            flags = fcntl(global_fd_socket, F_SETFL, flags | O_NONBLOCK);
            if ((bytes_read = recv(global_fd_socket, buf_rx, REQUEST_MAX_SIZE, 0)) < 0) {
                puts("Something got wrong!\n");
                break;
            }
            else if (bytes_read == 0) {
                printf("Connection closed by the remote end\n\r");
                return 0;
            }
            else {
                int32_t conv = htonl(filelen);
                char *data = (char*)&conv;
                int left = sizeof(conv);

                switch (buf_rx[1]) {
                    // Backtrace ja registrado no servidor
                    case '1':
                    break;
                    // Backtrace ainda nao registrado no servidor, envia o testcase 
                    case '3':
                        // Sinaliza o tamanho do testcase a ser enviado
                        flags = fcntl(global_fd_socket, F_SETFL, flags | O_NONBLOCK);
                        if ((bytes_send = send(global_fd_socket, data, left, 0)) < 0) {
                            perror("Error sending buf data");
                            return 1;
                        }

                        sleep(1);
                        // Envia o testcase
                        flags = fcntl(global_fd_socket, F_SETFL, flags | O_NONBLOCK);
                        if ((bytes_send = send(global_fd_socket, fileData, filelen, 0)) < 0) {
                            perror("Error sending buf data");
                            return 1;
                        }
                    break;
                    default:
                    break;
                }
            }
        } 
    }

    return 0;
}




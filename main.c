#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/time.h>
#include <unistd.h>
#include <signal.h>
#include <err.h>
#include <fcntl.h>
#include <wait.h>
#include <time.h>
#include <dirent.h>

// #define TARGETTOFUZZ        "exiv2"
// #define TARGETPARAMS        "pr -v"
#define TARGETTOFUZZ        "exif"
#define TARGETPARAMS        ""

#define TESTCASEDIR         "testcases"
#define TMPMUTATIONSDIR     "mutations"
#define TARGETFORMATFILE    "jpg"
#define MAX_FUZZ_ITERATIONS 1000000
#define FUZZ_SERVER_ADDR    "127.0.0.1"
#define FUZZ_SERVER_PORT    1337
#define BUFLEN              4096
#define MAX_FILENAME_SIZE   128
#define MAX_TESTCASES       100
#define FLIP_PERCENT        0.01

#define panic(X) fprintf(stderr, #X "\n");

// int  __fuzzServerConnectAndGetTestcase(char*, unsigned int port, unsigned char*);
int  getChildBacktraceAndVerifyHashExist(char*, char*, int, int);
void flip_bits(char*, int, float);
void insert_magic(char*, long, float);

typedef struct TESTCASE_ITEM {
  unsigned char filename[MAX_FILENAME_SIZE];
  unsigned char *fileData;
  int  filelen;
} TYPE_TESTCASE_ITEM;

char const *global_program_name;
int global_fd_socket;
// TYPE_TESTCASE_ITEM *global_backtraces_list = NULL;
/* ************************************************************************** */

unsigned char* createNewTestCase(unsigned char *data, int filelen, int counter) {

  FILE *write_ptr;
  int totalRemaining         = 0;
  int nwritten               = 0;
  int blockSize              = 0;
  unsigned char *newFileName;
  
  newFileName = malloc(MAX_FILENAME_SIZE);

  snprintf(newFileName,30,"mutations/subject-%d.jpg",counter);

  write_ptr = fopen(newFileName,"wb"); 
  if (write_ptr == NULL) {
    /* handle error */
    perror("file open for reading");
    exit(EXIT_FAILURE);
  }

  totalRemaining = filelen - nwritten;
  while (totalRemaining > 0) {
    blockSize = (totalRemaining >= BUFLEN) ? BUFLEN : totalRemaining;
    nwritten  = fwrite(data,1,blockSize,write_ptr);
    data+=nwritten;
    totalRemaining-=nwritten;
  }

  fclose(write_ptr);
  return newFileName;
}

unsigned char* get_bytes(char *filename, int *filelen) {

  FILE *fileptr;
  unsigned char *data;
  int length;

  fileptr = fopen(filename, "rb");  // Open the file in binary mode
  fseek(fileptr, 0, SEEK_END);      // Jump to the end of the file
  length = ftell(fileptr);          // Get the current byte offset in the file
  rewind(fileptr);                  // Jump back to the beginning of the file

  data = (char*) malloc(length);    // Enough memory for the file
  fread(data, length, 1, fileptr);  // Read in the entire file
  
  if(filelen)
    *filelen = length;

  fclose(fileptr);                  // Close the file
  return data;
}

/* Spawn a child process running a new program.  PROGRAM is the name
   of the program to run; the path will be searched for this program.
   ARG_LIST is a NULL-terminated list of character strings to be
   passed as the program's argument list.  Returns the process id of
   the spawned process.  */
void spawn(char* program, char* mutatedFile, int filelen, int counter)
{
  char shellBuffer[256];
  pid_t child_pid;
  char* arg_list[] = {
    TARGETTOFUZZ,
    mutatedFile,
    NULL
  }; 
   
  // dup both stdout and stderr and send them to /dev/null
  int fd = open("/dev/null", O_WRONLY);
  dup2(fd, 1);
  dup2(fd, 2);
  close(fd);

  /* Duplicate this process.  */
  child_pid = vfork();

  if (child_pid == -1) {
    // error, failed to fork()
  } 
  else if (child_pid != 0) {
    /* This is the parent process.  */
    int status;
    waitpid(child_pid, &status, 0);

    // It was terminated by a signal
    if (WIFSIGNALED(status)) {

      // int termsig = WTERMSIG(status);
      // printf("termsig: %d\n", termsig);

      // switch(termsig)
      // {
      //   case SIGSEGV:
      //     fputs("Caught SIGSEGV: Segmentation Fault\n", stderr);
      //     break;
      //   case SIGINT:
      //     fputs("Caught SIGINT: Interactive attention signal, (usually ctrl+c)\n",
      //           stderr);
      //     break;
      //   case SIGFPE:
      //     fputs("Caught SIGFPE: Floating Point Exception\n",
      //           stderr);
      //     break;
      //   case SIGILL:
      //     fputs("Caught SIGILL: Illegal instruction\n",
      //           stderr);
      //     break;
      //   case SIGTERM:
      //     fputs("Caught SIGTERM: a termination request was sent to the program\n",
      //           stderr);
      //     break;
      //   case SIGABRT:
      //     fputs("Caught SIGABRT: usually caused by an abort() or assert()\n", stderr);
      //     break;
      //   default:
      //     break;
      // }

      // Backtrace ja registrado
      if(getChildBacktraceAndVerifyHashExist("lastChildStackTrace.stacktrace", mutatedFile, filelen, counter)) {
        // Remove o testcase inutil
        // snprintf(shellBuffer, sizeof(shellBuffer), "rm %s", mutatedFile);
        // system(shellBuffer);
        // system("rm mutations/*");
      }
      // Backtrace ainda nao registrado
      else {
        // Salva o testcase 
        snprintf(shellBuffer, sizeof(shellBuffer), "mv %s faults/", mutatedFile);
        system(shellBuffer);
      }


    }
    else if (WEXITSTATUS(status)) {
    }

    if((counter % 10000) == 0)
      system("rm mutations/*");
    return;
  }
  else {
    /* Now execute PROGRAM, searching for it in the path.  */
    execvp(program, arg_list);

    /* The execvp function returns only if (an error occurs.  */
    fprintf (stderr, "an error occurred in execvp\n");
    _exit(EXIT_FAILURE); 
  }
}

int main(int argc, char **argv) {
  unsigned char testcaseDIR[256], *testcaseFileData, *mutatedFile, *mutatedFileData;
  unsigned int filelen, totalTestcases, randomIndex, iterCounter; 
  DIR *d;
  struct dirent *dir;
  struct TESTCASE_ITEM testcases[MAX_TESTCASES];
  struct timespec tstart={0,0}, tend={0,0};
  
  // Initialize the random seed
  srand((unsigned)time(NULL));
  
  // Obtem a listagem de testcases
  totalTestcases=0;
  d = opendir(TESTCASEDIR);
  if (d) {
    while ((dir = readdir(d)) != NULL) {
      // printf("%s\n", dir->d_name);
      if(strcmp(dir->d_name,".")==0 || strcmp(dir->d_name,"..")==0)
        continue;

      sprintf(testcases[totalTestcases].filename,"%s/%s",TESTCASEDIR,dir->d_name);

      testcaseFileData = get_bytes(testcases[totalTestcases].filename, &filelen);
      
      testcases[totalTestcases].filelen  = filelen;
      testcases[totalTestcases].fileData = malloc(filelen);
      memcpy(testcases[totalTestcases].fileData,testcaseFileData,filelen);

      free(testcaseFileData);
      totalTestcases++;
    }
    closedir(d);
  }
  
  // Configura libSegfault para capturar todas as excecoes dos child process
  putenv("SEGFAULT_SIGNALS=all");
  putenv("SEGFAULT_OUTPUT_NAME=./lastChildStackTrace.stacktrace");
  putenv("LD_PRELOAD=/lib/x86_64-linux-gnu/libSegFault.so");

  // global_program_name = argv[0];
  // global_fd_socket    = __fuzzServerConnectAndGetTestcase(FUZZ_SERVER_ADDR, FUZZ_SERVER_PORT, testcaseFileData);

  // if(global_fd_socket == -1) {
  //   perror("Erro ao se conectar com o servidor.\n");
  //   exit(EXIT_FAILURE);
  // }


  iterCounter = 0;
  randomIndex     = rand()%totalTestcases;
  mutatedFileData = malloc(testcases[randomIndex].filelen);
  do
  {
    // Copia dados do arquivo orginal para testcase a ser mutado
    memcpy(mutatedFileData, testcases[randomIndex].fileData, testcases[randomIndex].filelen);
    

    insert_magic(mutatedFileData, filelen, 0.01);    
    // flip_bits(mutatedFileData, filelen, 0.01); 

    mutatedFile = createNewTestCase(mutatedFileData, testcases[randomIndex].filelen, iterCounter);


    /* Spawn a child process running the specified command.  Ignore the
      returned child process id.  */
    spawn(TARGETTOFUZZ, mutatedFile, testcases[randomIndex].filelen, iterCounter); 
    iterCounter++;

    free(mutatedFile);

    // Seleciona outro testcase apos 1K iteracoes
    if((iterCounter % 1000) == 0) {
      // Remove as mutacoes inuteis produzidas ate agora
      system("rm mutations/*");

      // Escolhe um novo testcase
      randomIndex  = rand()%totalTestcases;
      mutatedFileData  = malloc(testcases[randomIndex].filelen);
    }
  } while (iterCounter < MAX_FUZZ_ITERATIONS);
  

  free(testcaseFileData);
  free(mutatedFileData);
  printf ("done with main program\n");
  return 0;
}

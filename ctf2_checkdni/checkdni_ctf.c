#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include<unistd.h>

#define CANARY_SIZE 5

char initial_canary[CANARY_SIZE];

void readCanary(){
  FILE *fp = fopen("canary.txt", "r");
  
  if (fp == NULL){
    perror("Error reading the file: canary.txt");
    exit(1);
  }
  
  fread(initial_canary,sizeof(char),CANARY_SIZE,fp);
  fclose(fp);

  return;
}

size_t b64_encoded_size(size_t inlen){
    size_t ret;

    ret = inlen;
    if (inlen % 3 != 0)
        ret += 3 - (inlen % 3);
    ret /= 3;
    ret *= 4;

    return ret;
}

char *b64_encode(const unsigned char *in, size_t len){
    const char b64chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    char   *out;
    size_t  elen;
    size_t  i;
    size_t  j;
    size_t  v;

    if (in == NULL || len == 0)
        return NULL;

    elen = b64_encoded_size(len);
    out  = malloc(elen+1);
    out[elen] = '\0';

    for (i=0, j=0; i<len; i+=3, j+=4) {
        v = in[i];
        v = i+1 < len ? v << 8 | in[i+1] : v << 8;
        v = i+2 < len ? v << 8 | in[i+2] : v << 8;

        out[j]   = b64chars[(v >> 18) & 0x3F];
        out[j+1] = b64chars[(v >> 12) & 0x3F];
        if (i+1 < len) {
            out[j+2] = b64chars[(v >> 6) & 0x3F];
        } else {
            out[j+2] = '=';
        }
        if (i+2 < len) {
            out[j+3] = b64chars[v & 0x3F];
        } else {
            out[j+3] = '=';
        }
    }

    return out;
}

char* read_png_to_base64(char* filename) {
    unsigned char* data = NULL;
    FILE* fp = fopen(filename, "rb");
    if (fp) {
        fseek(fp, 0, SEEK_END);
        size_t size = ftell(fp);
        rewind(fp);
        data = (unsigned char*) malloc(size);
        fread(data, 1, size, fp);
        fclose(fp);
        char* encoded_data = b64_encode(data, size);
        free(data);
        return encoded_data;
    } else {
        puts("Error reading the file: jnic.jpg");
        fflush(stdout);
    }
    return NULL;
}

void image(){
    char* foto = read_png_to_base64("jnic.jpg");
    puts(foto);
    fflush(stdout);
    return;
}

char letterDNI(int dni) {
  char letter[] = "TRWAGMYFPDXBNJZSQVHLCKE";

  return letter[dni%23];
}

int checkDNI_aux(char *dni) {
  if (strlen(dni)!=9)
      return 0;
  else
    return (letterDNI(atoi(dni))==dni[8]);
}

void checkDNI(char *dni){
  printf("\nLet's check if the DNI is correct...\n");
  //sleep(1);
  if (checkDNI_aux(dni))
    printf (" --> The DNI is correct!\n");
  else
    printf (" --> The DNI is not correct!\n");
  return;
}

void readDNI(){
  char current_canary[CANARY_SIZE];
  char dni[9];
  char aux_buffer[10];

  memcpy(current_canary,initial_canary,CANARY_SIZE);
 
  printf ("Enter your full DNI (without spaces): ");
  scanf("%s", aux_buffer);
  strncpy(dni, aux_buffer, strlen(aux_buffer)); // we delete the '\0'

  //check that the canary is not smashed
  if (memcmp(current_canary, initial_canary, CANARY_SIZE)) {
      printf("***** Stack Smashing Detected ***** : Canary Value Corrupt!\n");
      exit(-1);
  }

  dni[strlen(aux_buffer)] = '\0'; // we add it again once the canary is checked
  checkDNI(dni);
  return;

}

int main(int argc, char *argv[]) {
  setvbuf(stdout, NULL, _IONBF, 0);

  readCanary();
  readDNI();
   
  exit(0);
}
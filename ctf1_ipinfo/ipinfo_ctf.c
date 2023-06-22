#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <signal.h>

void readEnv(char creds[15]){
	char aux[15];
	FILE *fp = fopen(".env", "r");
	
	if (fp == NULL){
		perror("Error reading the file: .env");
		exit(1);
	}
	
	fgets(aux, sizeof(aux), fp);
	fclose(fp);
	strcpy(creds, aux);

	return;
}

void printEnvFile(){
	char token[15];
	readEnv(token);
	printf("token{%s}\n", token);
	fflush(stdout);
}

int isValidIpAddress(char *ipAddress){
    struct sockaddr_in sa;
    int result = inet_pton(AF_INET, ipAddress, &(sa.sin_addr));
    return result != 0;
}

void executeCommand(char ipAddress[15]){
	if(isValidIpAddress(ipAddress)){
		FILE *fp;
		char response[1035];
		char token[15];
		char finalCommand[60];

		readEnv(token);
		sprintf(finalCommand, "curl \"https://ipinfo.io/%s?token=%s\" 2>/dev/null", ipAddress, token);

		fp = popen(finalCommand, "r");
		if (fp == NULL) {
			printf("Failed to run command\n" );
			exit(1);
		}

		while (fgets(response, sizeof(response), fp) != NULL) {
			printf("%s", response);
		}
		printf("\n\n");

		pclose(fp);

	} else{
	    printf("Traceback (most recent call last):\n");
	    printf("\tError in 'executeCommand' function (%p).\n", executeCommand);
	    printf("InputError: the entered IP is not valid.\n\n");
	}
}

void readIP(){
	char ipAddress[15];
	printf("Enter the IP address to scan:\n");
	fflush(stdout);
	scanf("%s", ipAddress);
	executeCommand(ipAddress);
}

void intHandler(int dummy) {
    printf("\n\nThank you very much for using the application, see you soon!\n");
    exit(0);
}


int main(int argc, char *argv[]) {
	signal(SIGINT, intHandler);

	while(1){
		readIP();
	}

	return 0;
}

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <ctype.h>
#include <assert.h>
#include <errno.h>
#include <sys/mman.h>
#include <unistd.h>
#include "sha256.h"

#define MAX_LINE 1024
#define ERROR_MAX_LINES 40
#define MAX_COMMANDNAME_LEN 10

#define ERR_BAD_CMD 1
#define ERR_BAD_SYN 2
#define ERR_EXEC 3

char* getcommand(char*, char*);
int interpret_sign(char*, char*);

int main(int argc, char** argv) {
	char cmd[MAX_COMMANDNAME_LEN], errorbuf[MAX_LINE*ERROR_MAX_LINES];
	char* line = 0;
	size_t line_sz = 0;

	setlinebuf(stdout);
	while (1) {
		if (getline(&line, &line_sz, stdin) <= 0)
			break;
		line[strlen(line)-1] = 0;

		int error = ERR_BAD_CMD;
		char* args = getcommand(line, cmd);

		if (args) {
			if (!strcmp(cmd, "SIGN")) {
				error = interpret_sign(args, errorbuf);
                break; //puta gambiarra sem tempo pra debuggar
            }
			if (!strcmp(cmd, "END"))
				break;
		} else {
			error = ERR_BAD_SYN;
		}


		if (error) printf("ERROR BEGIN %s\n", cmd);
		switch (error) {
			case ERR_BAD_CMD: printf("Unknown command: %s\n", cmd); break;
			case ERR_BAD_SYN: printf("Bad syntax for %s\n", line); break;
			case ERR_EXEC: printf("%s", errorbuf); break;
			default: break;
		}
		if (error) 
            printf("ERROR END %s\n", cmd);
        else
            printf("OK %s\n", cmd);
		free(line); line = 0; line_sz = 0;
	}

    return 0;
}

char* getcommand(char* line, char* cmd) {
	while (*line && !isspace(*line) && *line != '\n')
		*cmd++ = *line++;
	return *line ? line+1 : 0;
}

int interpret_sign(char* filename, char* errorbuf) {
	SHA256_CTX ctx;

	FILE* file = fopen(filename, "a+");
	if (!file) {
		sprintf(errorbuf, "Could not open \"%s\" errno=%d: %s\n", filename, errno, strerror(errno));
		return ERR_EXEC;
	}

	fseek(file, 0, SEEK_END);
	size_t len = ftell(file);
	void* base = mmap(NULL, len, PROT_READ|PROT_WRITE, MAP_SHARED,
			          fileno(file), 0);
	if (base == MAP_FAILED) {
		sprintf(errorbuf, "mmap failed errno=%d: %s\n", errno, strerror(errno));
		return ERR_EXEC;
	}

	int32_t payload_sz = *((int32_t*)base); //JVM is big endian
	payload_sz = ((payload_sz<<24)&0xff000000)
			   | ((payload_sz<<8 )&0x00ff0000)
			   | ((payload_sz>>8 )&0x0000ff00)
			   | ((payload_sz>>24)&0x000000ff) ; //intel is little endian
    sha256_init(&ctx);
    sha256_update(&ctx, base+4, payload_sz);
    sha256_final(&ctx, base+4+payload_sz);

	munmap(base, len);
	fclose(file);
	return 0;
}


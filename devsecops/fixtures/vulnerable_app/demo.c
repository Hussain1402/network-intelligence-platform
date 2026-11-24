#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define API_TOKEN "DEMO_SECRET_TOKEN_123456789"

void copy_user_input(const char *input) {
    char buffer[16];
    strcpy(buffer, input);
}

int main(void) {
    char command[128];
    sprintf(command, "echo %s", "demo");
    system(command);
    printf("Demo application\n");
    return 0;
}

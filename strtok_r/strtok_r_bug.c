#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main() {
    char myStr[12] = "hello;world";
    char *saveptr;
    char *fstTok = strtok_r(myStr, ";", &saveptr);

    puts(fstTok);

    char myStr2[9] = ";foo;bar";
    char *saveptr2;
    char *fstTok2 = strtok_r(myStr2, ";", &saveptr2);

    puts(fstTok2);
}

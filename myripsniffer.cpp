
#include <iostream>
#include <cstring>
#include <string>

#include "riplib.h"

/* ------------------------------ */
char * ifce; /**< Interface name. */
/* ------------------------------ */

/**
 * @brief   Main function.
 * @param argc          Count of arguments.
 * @param argv          Arguments.
 * @returns Exit code. 
 */
int main(int argc, char *argv[]) {
    
    // -i
    if(argc == 3 && !strcmp(argv[1], "-i") ) {
        ifce = argv[2];
    } 
    // other - fail
    else printErrorAndExit("Usage: ./myripsniffer -i <interface>\n", 1);

    // connect to device
    Sniffer s(ifce);
    
    // Listen
    do {
        s.listen();
    } while(true);

    return 0;
}

#include <iostream>
#include <cstring>
#include <string>

#include "riplib.h"

/* ------------------------------ */
char * ifce = NULL; /**< Interface name. */
bool showLink = false;
bool showNetwork = false;
bool showTransport = false;
/* ------------------------------ */

void showUsage() { printErrorAndExit("Usage: ./myripsniffer -i <interface> [-l|--link] [-n|--network] [-t|--transport]", 1); }

/**
 * @brief   Main function.
 * @param argc          Count of arguments.
 * @param argv          Arguments.
 * @returns Exit code. 
 */
int main(int argc, char *argv[]) {
    
    if(argc < 3) showUsage();
    // -i
    for(int it = 1; it < argc; it++) {
        if(!strcmp(argv[it], "-i")) {
            if(it == argc-1) showUsage();
            ifce = argv[++it];
        } else if(!strcmp(argv[it],"-l") || !strcmp(argv[it],"--link")) {
            if(showLink) showUsage();
            showLink = true;
        } else if(!strcmp(argv[it],"-n") || !strcmp(argv[it],"--network")) {
            if(showNetwork) showUsage();
            showNetwork = true;
        } else if(!strcmp(argv[it],"-t") || !strcmp(argv[it],"--transport")) {
            if(showTransport) showUsage();
            showTransport = true;
        } else showUsage();
    }
    if(ifce == NULL) showUsage();
    
    // connect to device
    Sniffer s(ifce);
    
    // Listen
    std::cerr << "Listening...\n";
    do {
        s.listen();
    } while(true);

    return 0;
}
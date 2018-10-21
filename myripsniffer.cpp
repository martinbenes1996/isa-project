
#include <iostream>
#include <cstring>
#include <string>

#include "riplib.h"

/* ------------------------------ */
char * ifce = NULL; /**< Interface name. */
bool showLink = false;
bool showNetwork = false;
bool showTransport = false;
bool verbose = false;
/* ------------------------------ */

void showUsage() { printErrorAndExit("Usage: ./myripsniffer -i <interface> [-v|--verbose] [-l|--link] [-n|--network] [-t|--transport]", 1); }
void printPacket(Packet);

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
            if(ifce != NULL) showUsage();
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
        } else if(!strcmp(argv[it],"-v") || !strcmp(argv[it],"--verbose")) {
            if(verbose) showUsage();
            verbose = true;
        } else showUsage();
    }
    if(ifce == NULL) showUsage();
    
    // connect to device
    Sniffer s(ifce);
    
    // Listen
    std::cout << "Welcome to My RIP Sniffer!\n";
    std::cout << "Showing RIP traffic on the interface \"" << ifce << "\":\n\n";
    do {
        Packet p = s.listen();
        printPacket(p);
    } while(true);

    return 0;
}

void printPacket(Packet p) {
    static size_t counter = 1;
    if(!p.valid) { std::cout << "Invalid packet!\n"; return; }
    std::cout << "(" << counter << ") " << p.rip.protocol << " packet\n";
    if(showLink) {
        std::cout << "L2 (" << p.link.protocol << "):\t\t" << p.link.src << " -> " << p.link.dst << "\n";
    }
    if(showNetwork) {
        std::cout << "L3 (" << p.network.protocol << "):\t\t" << p.network.src << " -> " << p.network.dst << "\n";
    }
    if(showTransport) {
        std::cout << "L4 (" << p.transport.protocol << "):\t\t" << p.transport.src << " -> " << p.transport.dst << "\n";
    }
    std::cout << "L7 (" << p.rip.protocol << "):\t\t" << p.rip.message << "\n";
    if(verbose) {
        if(p.rip.isAuthentized) {
            std::cout << "Authentized with " << p.rip.authType
                      << " (password: \"" << p.rip.password << "\").\n";
        }

        std::cout << "Address / Subnet prefix or mask       Hop count\n";
        for(auto& it: p.rip.records) {
            std::cout << "| " << it.address << "/" << it.mask;
            for(unsigned x = 0; x < 38-(it.address.size()+it.mask.size()+1); x++) { std::cout << " "; }
            std::cout << it.metric << "\n"; 
        }

    } else {
        if(p.rip.records.size() > 0) { std::cout << "+ Routing Table Data\n"; }
    }
    std::cout << "\n\n";
    counter++;
    
}
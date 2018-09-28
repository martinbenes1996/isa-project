
#include <iostream>
#include <functional>
#include <cstring>
#include <climits>
#include <ctype.h>

char * ifce = NULL;
int addr[4] = {-1,};
int mask = -1;
int nexthop[4] = {-1,};
int metric = -1;
int rttag = -1;
char * passwd = NULL;

void printUsageAndExit() {
    std::cerr << "Usage: ./myripresponse {-i <interface>} -r <IPv4>/[8-30] {-n <IPv4>} {-m [0-16]} {-t [0-65535]} {-p <password>}\n";
    exit(1);
}

int parseInt(   const char * s, 
                std::function<bool(int)> inRange = [](int){ return true; },
                std::function<bool(char c)> isEnd = [](char c){ return isspace(c); },
                int* length = NULL) {

    long result = 0;
    int len = 0;
    for(unsigned i = 0; i < strlen(s); i++) {
        if( isdigit(s[i]) ) {
            result += s[i] - '0';
            if( inRange(result) ) printUsageAndExit();
            result *= 10;
            len = i+1;
        }
        else if( isEnd(s[i]) ) { 
            len = i;
            break;
        }
        else printUsageAndExit();
    }
    result /= 10;
    if( !inRange(result) || len == 0) printUsageAndExit();
    if( length != NULL ) *length = len;
    return (int)result;
}

int main(int argc, char *argv[]) {
    if(argc%2 != 0 && argc >= 3) {
        for(int i = 1; i < argc; i+=2) {
            // -i
            if( !strcmp(argv[i],"-i") ) {
                if(ifce != NULL) printUsageAndExit();
                else ifce = argv[i+1];
            }
            else if( !strcmp(argv[i],"-r") ) {
                if(addr[0] != -1) printUsageAndExit();
                if(sscanf(argv[i+1], "%d.%d.%d.%d/%d", &addr[0], &addr[1], &addr[2], &addr[3], &mask) != 5) printUsageAndExit();
            }
            else if( !strcmp(argv[i],"-n") ) {
                if(nexthop[0] != -1) printUsageAndExit();
                if(sscanf(argv[i+1], "%d.%d.%d.%d", &nexthop[0], &nexthop[1], &nexthop[2], &nexthop[3]) != 4) printUsageAndExit();
            }
            else if( !strcmp(argv[i],"-m") ) {
                if(metric != -1) printUsageAndExit();
                else metric = parseInt(argv[i+1], [](int x){return (x>=0)&&(x<=16);} );
            }
            else if( !strcmp(argv[i],"-t") ) {
                if(rttag != -1) printUsageAndExit();
                else rttag = parseInt(argv[i+1], [](int x){return (x>=0)&&(x<=65535);} );
            }
            // -p
            else if( !strcmp(argv[i],"-p") ) {
                if(passwd != NULL) printUsageAndExit();
                else passwd = argv[i+1];
            }
            // other
            else printUsageAndExit();
        }
    }
    else printUsageAndExit();




}
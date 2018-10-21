
#include <iostream>
#include <functional>
#include <cstring>
#include <climits>
#include <ctype.h>

#include "riplib.h"

/* ------------------------------------------------------------- */
const char * ifce = NULL;   /**< Interface name.*/
struct in6_addr addr;        /**< Address of the fake network. */
u_int8_t mask;              /**< Mask of the fake network. */
struct in6_addr nexthop;     /**< Address of fake route next-hop. */
u_int8_t metric;            /**< Hop-count. */
u_int16_t rttag;             /**< Route tag. */
const char * passwd = NULL; /**< Password. */

bool givenAddr = false;
bool givenNextHop = false;
bool givenMetric = false;
bool givenRtTag = false;
/* ------------------------------------------------------------- */

/**
 * @brief Prints the usage and then terminate the program.
 */
void printUsageAndExit() {
    std::cerr << "Usage: ./myripresponse {-i <interface>} -r <IPv4>/[8-30] {-n <IPv4>} {-m [0-16]} {-t [0-65535]} {-p <password>}\n";
    exit(1);
}


/**
 * @brief   Parses string into integer.
 * @param s         String including integer.
 * @param isRange   Function saying if input integer is in range of possible values.
 * @param isEnd     Function saying if input character is end of string.
 * @param length    If not NULL, function writes count of digits.
 * @returns Parsed integer.
 */
int parseInt(   const char * s, 
                std::function<bool(int)> inRange = [](int){ return true; },
                std::function<bool(char c)> isEnd = [](char c){ return isspace(c); },
                int* length = NULL) {
    
    long result = 0; // Return value
    int len = 0;     // Digit count

    for(unsigned i = 0; i < strlen(s); i++) { // go around string
        // digit
        if( isdigit(s[i]) ) {
            result += s[i] - '0';
            if( !inRange(result) ) printUsageAndExit();
            result *= 10;
            len = i+1;
        }
        // ending character
        else if( isEnd(s[i]) ) { 
            len = i;
            break;
        }
        // other - fail
        else printUsageAndExit();
    }
    result /= 10;
    
    // out of range || no number
    if( !inRange(result) || len == 0) printUsageAndExit();
    // return
    if( length != NULL ) *length = len;
    return (int)result;
}

/**
 * @brief   Main function.
 * @param argc          Count of arguments.
 * @param argv          Arguments.
 * @returns Exit code. 
 */
int main(int argc, char *argv[]) {
    // correct count
    if(argc%2 != 0 && argc >= 3) {
        std::function<bool(int)> inChar = [](int x){ return x >= 0 && x < 256; }; // function (i in <0;255>)

        for(int i = 1; i < argc; i+=2) { // go around argument couples

            // -i
            if( !strcmp(argv[i],"-i") ) {
                if(ifce != NULL) printUsageAndExit();
                else ifce = argv[i+1];
            }
            // -p
            else if( !strcmp(argv[i],"-p") ) {
                if(passwd != NULL) printUsageAndExit();
                else passwd = argv[i+1];
            }
        
            // -r
            else if( !strcmp(argv[i],"-r") ) {
                if( givenAddr ) printUsageAndExit();
                //char * addr, * 
                if(inet_pton(AF_INET6, argv[i+1], &addr) != 1) printUsageAndExit();
                // ...
                givenAddr = true;
            }
            // -n
            else if( !strcmp(argv[i],"-n") ) {
                if( givenNextHop ) printUsageAndExit();
                if(inet_pton(AF_INET6, argv[i+1], &nexthop) != 1) printUsageAndExit();
                // ...
                givenNextHop = true;
            }

            // -m
            else if( !strcmp(argv[i],"-m") ) {
                if( givenMetric ) printUsageAndExit();
                else metric = parseInt(argv[i+1], [](int x){return (x>=0)&&(x<=16);} );
                givenMetric = true;
            }
            // -t
            else if( !strcmp(argv[i],"-t") ) {
                if( givenRtTag ) printUsageAndExit();
                else rttag = parseInt(argv[i+1], [](int x){return (x>=0)&&(x<=65535);} );
                givenRtTag = true;
            }
            
            // other
            else printUsageAndExit();
        }

        // set default
        if( !givenAddr ) printUsageAndExit();
        if( !givenMetric ) metric = 1;
        if( !givenNextHop ) inet_pton(AF_INET6, "::", &nexthop);
        if( !givenRtTag ) rttag = 0;
        if( passwd == NULL ) passwd = "";
        if( ifce == NULL ) ifce = ""; // ???

        void * p = generateRIPResponse(addr, mask, metric, nexthop, rttag);
        RIPHdr * hdr = (RIPHdr *)p;
        std::cout << hdr->comm << " " << hdr->version << " " << hdr->res1 << "\n";

    }

    // incorrect count - fail
    else printUsageAndExit();


    //std::cout << "Interface: " << ifce << "\n";
    //std::cout << "Address: " << addr[0] << "." << addr[1] << "." << addr[2] << "." << addr[3] << "/" << mask << "\n";
    //std::cout << "Next hop: " << nexthop[0] << "." << nexthop[1] << "." << nexthop[2] << "." << nexthop[3] << "\n";
    //std::cout << "Metric: " << metric << "\n";
    //std::cout << "Route Tag: " << rttag << "\n";
    //std::cout << "Password: " << passwd << "\n";


}
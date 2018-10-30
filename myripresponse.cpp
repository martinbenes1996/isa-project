/**
 * @file    MyRipResponse.cpp
 * @author  xbenes49
 * @brief   RIP Response packet generator.
 */

// C
#include <climits>
#include <ctype.h>
#include <string.h>
#include <unistd.h>
// C++
#include <iostream>
#include <functional>
// Net
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
// My libraries
#include "lib.h"
#include "netlib.h"


/* ------------------------------------------------------------- */
namespace {
    const char * ifce = NULL;   /**< Interface name.*/
    struct in6_addr addr;        /**< Address of the fake network. */
    u_int8_t mask;              /**< Mask of the fake network. */
    struct in6_addr nexthop;     /**< Address of fake route next-hop. */
    u_int8_t metric;            /**< Hop-count. */
    u_int16_t rttag;             /**< Route tag. */
    const char * passwd = NULL; /**< Password. */
}
/* ------------------------------------------------------------- */


/**
 * @brief Prints the usage and then terminate the program.
 */
void printUsageAndExit() {
    std::cerr << "Usage: ./myripresponse {-i <interface>} -r <IPv6>/[16-128] {-n <IPv4>} {-m [0-16]} {-t [0-65535]} {-p <password>}\n";
    exit(1);
}

void printErrnoAndExit() {
    std::cerr << strerror(errno) << "\n";
    exit(errno);
}

/* ---------------------- if.h functions ------------------------ */
/**
 * @brief Returns link local IPv6 of given interface.
 * @param interface             Interface name.
 * @returns Link local IPv6.
 */
std::string getLinkLocalAddress(std::string);
/**
 * @brief Returns interface index of given interface.
 * @param interface             Interface name.
 * @returns Interface index.
 */
int getInterfaceIndex(std::string);
/* -------------------------------------------------------------- */

/**
 * @brief RIP Response Generator.
 * @param address       Address.
 * @param prefix        Address prefix.
 * @param metric        Metric.
 * @param nexthop       Next hop address.
 * @param tag           Route tag.
 * @returns Memory with generated packet. Never free.
 *          After second call the memory is reused.
 */
void * generateRIPResponse(struct in6_addr address,
                           u_int8_t prefix,
                           u_int8_t metric = 1,
                           struct in6_addr nexthop = in6_addr{0},
                           u_int16_t tag = 0);

/* --------------------- main function -------------------------- */
/**
 * @brief Parses args. Saves to the global variables.
 * @param argc          Argument count.
 * @param argv          Arguments.
 */
void parseArgs(int, char*[]);
/**
 * @brief   Main function.
 * @param argc          Count of arguments.
 * @param argv          Arguments.
 * @returns Exit code. 
 */
int main(int argc, char *argv[]) {
    // parse arguments
    parseArgs(argc, argv);
    
    // open socket
    int fd;
    if((fd = socket(AF_INET6, SOCK_DGRAM, 0)) < 0)
        printErrnoAndExit();

    // source
    struct sockaddr_in6 localaddr;
    memset(&localaddr, 0, sizeof(struct sockaddr_in6));
    localaddr.sin6_family = AF_INET6;
    localaddr.sin6_port = htons(521);
    inet_pton(AF_INET6, getLinkLocalAddress(ifce).c_str(), &localaddr.sin6_addr);
    localaddr.sin6_scope_id = getInterfaceIndex(ifce);
    //std::cerr << ip2str(localaddr.sin6_addr) << " " << localaddr.sin6_scope_id << "\n";
    bind(fd, (struct sockaddr *)&localaddr, sizeof(localaddr));

    // destination
    struct sockaddr_in6 address;
    memset(&address, 0, sizeof(address));
    address.sin6_family = AF_INET6;
    address.sin6_port = htons(521);
    inet_pton(AF_INET6, "ff02::9", &address.sin6_addr);

    // bind to device
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifce, 16);
    if (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, (void *)&ifr, sizeof(ifr)) < 0)
        printErrnoAndExit();

    // set hop limit
    unsigned hoplimit = 255;
    if(setsockopt(fd, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, (void*)&hoplimit, sizeof(int)) < 0)
        printErrnoAndExit();

    // generate RIP packet
    void * p = generateRIPResponse(addr, mask, metric, nexthop, rttag);
    size_t packetsize = ripHdrSize+2*ripngRRSize;
    
    std::cout << "Welcome to My RIP Response!\n";
    std::cout << "Generating fake RIP Response on the interface \"" << ifce << "\":\n\n";

    // sending loop
    do {
        sendto(fd, p, packetsize, 0, (struct sockaddr*)&address, sizeof address);

        // 30 s refresh time (RIP Specific) with printing.
        std::cout << "Sent RIP Response.                 \n";
        for(int i = 0; i < 9; i++) {
            std::cout << "\rWaiting 30 s [";
            int j;
            for(j = 0; j < 9; j++) std::cout << ((i >= j)?"#":" ");
            std::cout << "]" << std::flush;
            sleep(3);
        }
        std::cout << "\r";
    } while(true);
    
}
/* -------------------------------------------------------------- */

// https://stackoverflow.com/questions/14436550/access-link-local-address-using-c
std::string getLinkLocalAddress(std::string interface) {
    // get all addresses from all interfaces
    struct ifaddrs *ifaddr;
    if(getifaddrs(&ifaddr) < 0) {
        freeifaddrs(ifaddr);
        printErrnoAndExit();
    }
    // iterate over
    for(struct ifaddrs* ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        // ignore all except IPv6
        if(ifa->ifa_addr->sa_family != AF_INET6) continue;
        // match name
        struct sockaddr_in6 *curr = (struct sockaddr_in6 *)ifa->ifa_addr;
        if(interface != ifa->ifa_name) continue;
        // local (prefix 0xfe80)
        if((curr->sin6_addr.s6_addr[0] == 0xfe) && (curr->sin6_addr.s6_addr[1] == 0x80)) {
            // found
            freeifaddrs(ifaddr);
            return ip2str(curr->sin6_addr);
        }
    }
    // not found
    freeifaddrs(ifaddr);
    printErrorAndExit("Unknown link-local address", 5);
    return ""; // prevent warning
}
//https://android.googlesource.com/platform/bionic.git/+/android-4.4.2_r1/libc/bionic/if_nametoindex.c
int getInterfaceIndex(std::string interface) {
    int index = 0, ctl_sock;
    // set interface name
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, interface.c_str(), IFNAMSIZ);
    // open socket
    if((ctl_sock = socket(AF_INET, SOCK_DGRAM, 0)) >= 0) {
        // get index
        if(ioctl(ctl_sock, SIOCGIFINDEX, &ifr) >= 0) {
            index = ifr.ifr_ifindex;
        }
        // close socket
        close(ctl_sock);
    }
    // get index
    if(index > 0) return index;
    // not found
    printErrorAndExit("Unknown interface index", 5);
    return 0;
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

void parseArgs(int argc, char *argv[]) {
    // correct count
    if(argc%2 == 0 || argc < 3) printUsageAndExit();
    // indicators
    bool givenAddr = false;
    bool givenNextHop = false;
    bool givenMetric = false;
    bool givenRtTag = false;

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
            std::string s(argv[i+1]);
            std::string delimiter("/");
            size_t pos = 0;
                
            std::string token;

            if((pos = s.find(delimiter)) != std::string::npos) {
                token = s.substr(0, pos);
                s.erase(0, pos + delimiter.length());
            } else printUsageAndExit();

            if(inet_pton(AF_INET6, token.c_str(), &addr) != 1) printUsageAndExit();
            mask = parseInt(s.c_str(), [](int i){return (i>=16)&&(i<=128);});

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
    if( ifce == NULL ) printUsageAndExit();
    if( !givenAddr ) printUsageAndExit();
    if( !givenMetric ) metric = 1;
    if( !givenNextHop ) inet_pton(AF_INET6, "::", &nexthop);
    if( !givenRtTag ) rttag = 0;
    if( passwd == NULL ) passwd = "";
}

void * generateRIPResponse(struct in6_addr address,
                           u_int8_t prefix,
                           u_int8_t metric,
                           struct in6_addr nexthop,
                           u_int16_t tag) {
    // memory & header pointers
    static unsigned char mem[ripHdrSize + 2*ripngRRSize];
    struct RIPHdr *p = (struct RIPHdr*)mem;
    
    struct RIPngRouteRecord *nexthoprr =
                    (struct RIPngRouteRecord *)(mem + ripHdrSize + ripngRRSize);
    
    struct RIPngRouteRecord * rr = 
                    (struct RIPngRouteRecord *)(mem + ripHdrSize);

    // RIPng header
    p->comm = 2;
    p->version = 0x1; // Version RIPng
    p->res1 = 0;
    // fake record
    rr->dst = address;
    rr->tag = htons(tag);
    rr->prefix = prefix;
    rr->metric = metric;
    // next hop record
    nexthoprr->dst = nexthop;
    nexthoprr->tag = 0x0;
    nexthoprr->prefix = 0x0;
    nexthoprr->metric = 0xFF;

    // return data
    return (void *)mem;
}

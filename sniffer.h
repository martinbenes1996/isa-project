/**
 * @file    Sniffer.h
 * @author  xbenes49
 * @brief   Sniffer class definition. Cover for libpcap.
 */
#ifndef SNIFFER_H
#define SNIFFER_H

// C++
#include <iostream>
#include <iomanip>
#include <string>
#include <sstream>
#include <vector>
// NET
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>
#include <sys/socket.h>
// PCAP
#include <pcap/pcap.h>
// My libraries
#include "lib.h"
#include "netlib.h"


/**
 * @brief Prints error and exits.
 * @param error         PCAP error code.
 * @param errcode       Error code.
 */
void printErrorAndExit(int error, int errcode) {
    printErrorAndExit(pcap_statustostr(error), errcode);
}

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

constexpr size_t ethHdrSize = sizeof(struct ether_header); /**< Size of ethernet header. */
constexpr size_t ipv4HdrSize = sizeof(struct ip);   /**< Size of IPv4 header. */
constexpr size_t ipv6HdrSize = sizeof(struct ip6_hdr);  /**< Size of IPv6 header. */
constexpr size_t udpHdrSize = sizeof(struct udphdr); /**< Size of UDP header. */

// inspired by http://www.tcpdump.org/pcap.html
// inspired by https://www.devdungeon.com/content/using-libpcap-c
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


std::string command2str(u_int8_t c) {
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
std::string authType2str(u_int8_t at, bool& valid) {
    switch(at) {
        case 1: return "IP Route";
        case 2: return "Simple Password";
        case 3: return "MD5";
        default: valid = false; return "Unknown Authentication Type";
    }
}

// https://tools.ietf.org/html/rfc1700
Packet Sniffer::parseRIP(struct pcap_pkthdr* header, const u_char* data) {
    // create packet
    Packet p;
    long datasize = header->caplen;

    // Ethernet
    struct ether_header* eth = (struct ether_header*)data;
    p.link.src = mac2str(eth->ether_shost);
    p.link.dst = mac2str(eth->ether_dhost);
    p.link.protocol = "Ethernet";
    data += ethHdrSize;
    datasize -= ethHdrSize;

    // IP
    // IPv4
    if(eth->ether_type == 0x0008) {    
        struct ip *ip = (struct ip *)data;
        p.network.protocol = "IPv4";
        p.network.src = ip2str( ip->ip_src );
        p.network.dst = ip2str( ip->ip_dst );
        data += ipv4HdrSize;
        datasize -= ipv4HdrSize;
    // IPv6
    } else if(eth->ether_type == 0xDD86) {
        struct ip6_hdr *ip = (struct ip6_hdr *)data;
        p.network.protocol = "IPv6";
        p.network.src = ip2str( ip->ip6_src );
        p.network.dst = ip2str( ip->ip6_dst );
        data += ipv6HdrSize;
        datasize -= ipv6HdrSize;
    // error
    } else {
        p.valid = false;
        return p;
    }

    // UDP
    struct udphdr * udp = (struct udphdr*)data;
    p.transport.protocol = "UDP";
    p.transport.src = std::to_string(ntohs(udp->uh_sport));
    p.transport.dst = std::to_string(ntohs(udp->uh_dport));
    data += udpHdrSize;
    datasize -= udpHdrSize;

    // RIP
    struct RIPHdr * rip = (struct RIPHdr*)data;
    p.rip.message = command2str( rip->comm );
    data += ripHdrSize;
    datasize -= ripHdrSize;

    // RIPv1/2
    if(p.transport.dst == "520") {
        // version
        if(rip->version == 0x01) p.rip.protocol = "RIPv1";
        else if(rip->version == 0x02) p.rip.protocol = "RIPv2";
        else { p.valid = false; return p; }

        // authentication
        struct RIPAuthHdr * ripAuth = (struct RIPAuthHdr *)data;
        if(ripAuth->fill == 0xFFFF) {
            p.rip.isAuthentized = true;
            bool valid = true;
            p.rip.authType = authType2str( ntohs(ripAuth->type), valid);
            p.valid = valid;
            // IP routes
            if(ntohs(ripAuth->type) == 0x01) {
                p.rip.isAuthentized = false;
            // Simple Password
            } else if(ntohs(ripAuth->type) == 0x02) {
                p.rip.password = std::string(ripAuth->password);
        
            // MD5 authentication
            } else if(ntohs(ripAuth->type) == 0x03) {
                // read header
                short offset = ntohs(((short *)ripAuth)[2]);
                int len = ((char *)ripAuth)[7];
                datasize -= len;
                if(datasize < 0) {
                    p.valid = false;
                    return p;
                }
                unsigned char * key = ((unsigned char*)rip)+offset+4;
                // parse MD5 key
                std::stringstream ss;
                ss << std::hex;
                for(int it = 0; it < len - 4; it++) {
                    ss << std::setw(2) << std::setfill('0') << (int)key[it];
                }
                p.rip.password = ss.str();
            }
        
            data += ripAuthHdrSize;
            datasize -= ripAuthHdrSize;
        } else if(ripAuth->fill == 0x0000) {
            p.rip.isAuthentized = false;
        } else {
            p.valid = false;
            return p;
        }

        // routing table records
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

    // RIPng
    } else if(p.transport.dst == "521") {
        // version
        if(rip->version == 0x01) p.rip.protocol = "RIPng";
        else { p.valid = false; return p;}
        p.rip.isAuthentized = false;
        // routing table records
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

    // return packet
    return p;
}

#endif // SNIFFER_H
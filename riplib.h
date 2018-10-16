
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


// inspired by http://www.tcpdump.org/pcap.html
// inspired by https://www.devdungeon.com/content/using-libpcap-c

/**
 * @brief Prints error and exits.
 * @param error         PCAP error code.
 * @param errcode       Error code.
 */
void printErrorAndExit(int error, int errcode) {
    std::cerr << pcap_statustostr(error) << "\n";
    exit(errcode);
}
/**
 * @brief Prints error and exits.
 * @param error         String to print.
 * @param errcode       Error code.
 */
void printErrorAndExit(std::string error, int errcode) {
    std::cerr << error << "\n";
    exit(errcode);
}

struct RIPngHeader {
    uint8_t command;
    uint8_t version;
    uint16_t zero;
    struct in6_addr addr;
    uint16_t route_tag;
    uint8_t prefix_length;
    uint8_t metric;
};

// https://github.com/lohith-bellad/RIPv2/blob/master/router.h
// RIP payload structure 
struct RIPRouteRecord {
	__u16	family;
	__u16	res2;
	in_addr	address;
	in_addr	res3;
	__u32	res4;
	__u32	metric;
}; 

struct RIPngRouteRecord {
	struct in6_addr	dst;
	u_int16_t	tag;
	u_int8_t	prefix;
	u_int8_t	metric;
};

// RIP header structure 
struct RIPHdr {
	__u8	comm;
	__u8	version;
	__u16	res1;
};

constexpr size_t ethHdrSize = sizeof(struct ether_header);
constexpr size_t ipv4HdrSize = sizeof(struct ip);
constexpr size_t ipv6HdrSize = sizeof(struct ip6_hdr);
constexpr size_t udpHdrSize = sizeof(struct udphdr);
constexpr size_t ripHdrSize = sizeof(struct RIPHdr);
constexpr size_t ripRRSize = sizeof(struct RIPRouteRecord);
constexpr size_t ripngRRSize = sizeof(struct RIPngRouteRecord);


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

struct RouteRecord {
    std::string address;
    std::string mask;
    std::string route;
    std::string metric;
} records;

struct Packet {
    bool valid = true;
    struct {
        std::string protocol;
        std::string src;
        std::string dst;
    } link;
    struct {
        std::string protocol;
        std::string src;
        std::string dst;
    } network;
    struct {
        std::string protocol;
        std::string src;
        std::string dst;
    } transport;
    struct {
        std::string protocol;
        std::string message;
        std::vector<struct RouteRecord> records;
    } rip;
};

class Sniffer {
    public:
        Sniffer(std::string ifce) {
            char errbuf[PCAP_ERRBUF_SIZE];
            int status;

            // get ip and mask
            bpf_u_int32 mask, ip;
            status = pcap_lookupnet(ifce.c_str(), &ip, &mask, errbuf);
            if(status == -1) {
                std::cerr << errbuf << "\n";
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

        Packet listen() {
            struct pcap_pkthdr* header;
            const u_char * data;
            int status;
            
            do {
                status = pcap_next_ex(mhandle, &header, &data);
                if(status == PCAP_ERROR) { printErrorAndExit(pcap_geterr(mhandle), 4); }
                if(header->len < ethHdrSize+ipv4HdrSize+udpHdrSize+ripHdrSize) { Packet p; p.valid = false; return p; }
            } while(status != 0);
            
            return parseRIP(header, data);
        }

        Packet parseRIP(struct pcap_pkthdr*, const u_char*);

        /**
         * @brief Destructor
         */
        ~Sniffer() { pcap_close(mhandle); }
    private:
        pcap_t *mhandle;
        struct bpf_program mfilter;
};

std::string mac2str(u_int8_t* mac) {
    char tmp[18];
    snprintf(tmp, sizeof(tmp), "%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return std::string(tmp);
}
std::string ip2str(struct in_addr* ip) {
    return std::string( inet_ntoa(*ip) );
}
std::string ip2str(struct in6_addr * ip) {
    char buffer[INET6_ADDRSTRLEN];
    if( inet_ntop(AF_INET6, (void*)ip->s6_addr, buffer, sizeof(buffer)) == NULL )
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
        p.network.src = ip2str( &ip->ip_src );
        p.network.dst = ip2str( &ip->ip_dst );
        data += ipv4HdrSize;
        datasize -= ipv4HdrSize;

    } else if(eth->ether_type == EtherType_IPv6) {  // IPv6
        struct ip6_hdr *ip = (struct ip6_hdr *)data;
        p.network.protocol = "IPv6";
        p.network.src = ip2str( &ip->ip6_src );
        p.network.dst = ip2str( &ip->ip6_dst );
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

        if((datasize % ripRRSize) != 0) { p.valid = false; return p; }
        while(datasize > 0) {
            struct RIPRouteRecord* riprecord = (struct RIPRouteRecord*)data;
            RouteRecord route;
            route.address = ip2str(&riprecord->address);
            route.mask = ip2str(&riprecord->res3);
            route.route = "???";
            route.metric = std::to_string(riprecord->metric);
            p.rip.records.push_back(route);

            data += ripRRSize;
            datasize -= ripRRSize;
        }

    /* ----------------- RIPng ------------------- */
    } else if(p.transport.dst == "521") {
        if(rip->version == VersionRIPng) p.rip.protocol = "RIPng";
        else { p.valid = false; return p;}

        if((datasize % ripngRRSize) != 0) { p.valid = false; return p; }
        while(datasize > 0) {
            struct RIPngRouteRecord* riprecord = (struct RIPngRouteRecord*)data;
            RouteRecord route;
            route.address = ip2str(&riprecord->dst);
            route.mask = std::to_string(riprecord->prefix);
            route.route = "???";
            route.metric = std::to_string(riprecord->metric);
            p.rip.records.push_back(route);

            data += ripngRRSize;
            datasize -= ripngRRSize;
        }
    }

    return p;
}

//struct RouteRecord {
//    std::string address;
//    std::string mask;
//    std::string route;
//    std::string metric;
//} records;

//struct RIPngRouteRecord {
//	struct in6_addr	rip6_dest;
//	u_int16_t	rip6_tag;
//	u_int8_t	rip6_plen;
//	u_int8_t	rip6_metric;
//};

//struct RIPRouteRecord {
//	__u16	family;
//	__u16	res2;
//	__u32	address;
//	__u32	res3;
//	__u32	res4;
//	__u32	metric;
//}; 

// struct riphdr {
//	__u8	comm;
//	__u8	version;
//	__u16	res1;
//};

// struct udphdr {
//	u_short	uh_sport;		/* source port */
//	u_short	uh_dport;		/* destination port */
//	u_short	uh_ulen;		/* udp length */
//	u_short	uh_sum;			/* udp checksum */
//};


//struct ip6_hdr {
//	union {
//		struct ip6_hdrctl {
//			u_int32_t ip6_un1_flow;	/* 20 bits of flow-ID */
//			u_int16_t ip6_un1_plen;	/* payload length */
//			u_int8_t  ip6_un1_nxt;	/* next header */
//			u_int8_t  ip6_un1_hlim;	/* hop limit */
//		} ip6_un1;
//		u_int8_t ip6_un2_vfc;	/* 4 bits version, top 4 bits class */
//	} ip6_ctlun;
//	struct in6_addr ip6_src;	/* source address */
//	struct in6_addr ip6_dst;	/* destination address */
//} __packed;


//struct ip {
//#if BYTE_ORDER == LITTLE_ENDIAN 
//	u_char	ip_hl:4,		/* header length */
//		ip_v:4;			/* version */
//#endif
//#if BYTE_ORDER == BIG_ENDIAN 
//	u_char	ip_v:4,			/* version */
//		ip_hl:4;		/* header length */
//#endif
//	u_char	ip_tos;			/* type of service */
//	short	ip_len;			/* total length */
//	u_short	ip_id;			/* identification */
//	short	ip_off;			/* fragment offset field */
//#define	IP_DF 0x4000			/* dont fragment flag */
//#define	IP_MF 0x2000			/* more fragments flag */
//	u_char	ip_ttl;			/* time to live */
//	u_char	ip_p;			/* protocol */
//	u_short	ip_sum;			/* checksum */
//	struct	in_addr ip_src,ip_dst;	/* source and dest address */
//};
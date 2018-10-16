
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
struct rippayload {
	__u16	family;
	__u16	res2;
	__u32	address;
	__u32	res3;
	__u32	res4;
	__u32	metric;
}; 
 
// RIP header structure 
struct riphdr {
	__u8	comm;
	__u8	version;
	__u16	res1;
};

constexpr size_t ethHdrSize = sizeof(struct ether_header);
constexpr size_t ipv4HdrSize = sizeof(struct ip);
constexpr size_t ipv6HdrSize = sizeof(struct ip6_hdr);
constexpr size_t udpHdrSize = sizeof(struct udphdr);
constexpr size_t ripHdrSize = sizeof(struct riphdr);
constexpr size_t ripPLHdrSize = sizeof(struct rippayload);


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

        void listen() {
            struct pcap_pkthdr* header;
            const u_char * data;
            int status;

            status = pcap_next_ex(mhandle, &header, &data);
            if(status == 1) { // received
                if(header->len < ethHdrSize+ipv4HdrSize+udpHdrSize+ripHdrSize+ripPLHdrSize) {
                    std::cerr << "Broken packet!\n";
                    return;
                }
                //std::cerr << header->len << " B, but only " << header->caplen << " B captured.\n";
                std::cerr << "-------------------------\n";
                parseRIP(header, data);
                std::cerr << "-------------------------\n\n";
            }
            else if(status == 0) {} // packets are being read
            else if(status == PCAP_ERROR) { printErrorAndExit(pcap_geterr(mhandle), 4); }
        }

        void parseRIP(struct pcap_pkthdr*, const u_char*);

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
std::string version2str(__u8 v, u_short port) {
    if(port == 520){
        if(v == 0x1) { return "RIPv1"; }
        else if(v == 0x2) { return "RIPv2"; }
    }   
    else if(port == 521) {
        if(v == 0x1) { return "RIPng"; }
    }
    return "Unsupported RIP version";
}

#define EtherType_IPv4 0x0008
#define EtherType_IPv6 0xDD86

// https://tools.ietf.org/html/rfc1700
#define Protocol_UDP 7
#define Protocol_RIPv2	0x11

void Sniffer::parseRIP(struct pcap_pkthdr* header, const u_char* data) {

    /* ----------------- ETHERNET ------------------- */
    size_t datasize = header->caplen;

    struct ether_header* eth = (struct ether_header*)data;
    data += ethHdrSize;
    datasize -= ethHdrSize;

    std::string macsrc = mac2str(eth->ether_shost);
    std::string macdst = mac2str(eth->ether_dhost);
    std::cerr << macsrc << " -> " << macdst << "\n";

    /* ----------------- IP ------------------- */
    std::string ipsrc, ipdst;
    std::string networkprotocol;
    
    if(eth->ether_type == EtherType_IPv4) { // IPv4
        networkprotocol = "IPv4";
        struct ip *ip = (struct ip *)data;
        ipsrc = ip2str( &ip->ip_src );
        ipdst = ip2str( &ip->ip_dst );

        data += ipv4HdrSize;
        datasize -= ipv4HdrSize;
    } else if(eth->ether_type == EtherType_IPv6) { // IPv6
        networkprotocol = "IPv6";
        struct ip6_hdr *ip = (struct ip6_hdr *)data;
        ipsrc = ip2str( &ip->ip6_src );
        ipdst = ip2str( &ip->ip6_dst );

        data += ipv6HdrSize;
        datasize -= ipv6HdrSize;
    } else {
        std::cerr << "Unsupported EtherType!\n";
        return;
    }
    std::cerr << networkprotocol << ": " << ipsrc << " -> " << ipdst << "\n";

    /* ----------------- UDP ------------------- */
    struct udphdr * udp = (struct udphdr*)data;
    u_short portsrc = ntohs(udp->uh_sport);
    u_short portdst = ntohs(udp->uh_dport);


    std::cerr << portsrc << " -> " << portdst << "\n";

    data += udpHdrSize;
    datasize -= udpHdrSize;

    /* ----------------- RIPv2 ------------------- */
    struct riphdr * rip = (struct riphdr*)data;
    std::string command = command2str( rip->comm );
    std::string version = version2str( rip->version, portdst);

    std::cerr << version << ": " << command << "\n";

    data += ripHdrSize;
    datasize -= ripHdrSize;
    
}

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
#ifndef MYNETINET_H
#define MYNETINET_H

#include <netinet/in.h>


// RIP header structure 
struct RIPHdr {
	__u8	comm;
	__u8	version;
	__u16	res1;
};


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

#endif // MYNETINET_H
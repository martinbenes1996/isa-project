#ifndef MYNETINET_H
#define MYNETINET_H

#include <netinet/in.h>

struct RIPAuthHdr {
	__u16 fill;
	__u16 type;
	char password[16];
};

// RIP header structure 
struct RIPHdr {
	__u8	comm;
	__u8	version;
	__u16	res1;
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
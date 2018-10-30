/**
 * @file    NetLib.h
 * @author  xbenes49
 * @brief   Essential definitions of net datatypes and functions.
 */

#ifndef NETLIB_H
#define NETLIB_H

// C++
#include <string>
// Net
#include <netinet/in.h>
// My libraries
#include "lib.h"

// https://github.com/lohith-bellad/RIPv2/blob/master/router.h

/**
 * @brief RIP Header.
 */
struct RIPHdr {
	u_int8_t	comm;
	u_int8_t	version;
	u_int16_t	res1;
};

/**
 * @brief RIPv2 Authentication Header.
 */
struct RIPAuthHdr {
	u_int16_t fill; /**< 16bit fill. */
	u_int16_t type; /**< Type of authentication. */
	char password[16]; /**< Password. */
};

/**
 * @brief RIP Routing Table Record.
 */
struct RIPRouteRecord {
	u_int16_t	family; /**< Family of address. */
	u_int16_t	res2; 	/**< Route tag. */
	in_addr	address;	/**< Address. */
	in_addr	res3;		/**< Subnet mask. */
	u_int32_t	res4;	/**< Next hop. */
	u_int32_t	metric;	/***/
}; 

struct RIPngRouteRecord {
	struct in6_addr	dst;
	u_int16_t	tag;
	u_int8_t	prefix;
	u_int8_t	metric;
};

constexpr size_t ripHdrSize = sizeof(struct RIPHdr);
constexpr size_t ripAuthHdrSize = sizeof(struct RIPAuthHdr);
constexpr size_t ripRRSize = sizeof(struct RIPRouteRecord);
constexpr size_t ripngRRSize = sizeof(struct RIPngRouteRecord);

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

#endif // MYNETINET_H
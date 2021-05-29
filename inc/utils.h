#ifndef __UTILS_H__
#define __UTILS_H__

#include <iostream>
#include <sys/types.h>  // uint8_t
#include <sys/socket.h>
#include <linux/if_packet.h> // struct sock_addrll
#include <netinet/ip.h> // struct ip, IPPROTO_UDP, INET_ADDRSTRLEN
#include <netinet/ether.h> // struct ether_header
#include <netinet/udp.h> // struct ether_header
#include <net/if.h> // IFNAMSIZstruct ifreq
#include <string.h> // strcpy
#include <sys/ioctl.h> // ioctl()
#include <string.h>
#include <arpa/inet.h> // inet_pton

#define ETH_HDRLEN 14
#define IP4_HDRLEN 20
#define UDP_HDRLEN 8
#define PACKETSIZE 65535

#define TRY(x)                                                  \
  do {                                                          \
    int __rc = (x);                                             \
    if( __rc < 0 ) {                                            \
      fprintf(stderr, "ERROR: TRY(%s) failed\n", #x);           \
      fprintf(stderr, "ERROR: at %s:%d\n", __FILE__, __LINE__); \
      fprintf(stderr, "ERROR: rc=%d errno=%d (%s)\n",           \
              __rc, errno, strerror(errno));                    \
      abort();                                                  \
    }                                                           \
  } while( 0 )


#define TEST(x)                                                 \
  do {                                                          \
    if( ! (x) ) {                                               \
      fprintf(stderr, "ERROR: TEST(%s) failed\n", #x);          \
      fprintf(stderr, "ERROR: at %s:%d\n", __FILE__, __LINE__); \
      abort();                                                  \
    }                                                           \
  } while( 0 )



void InitIp4Header(struct ip* ip_header, std::string src_ip, std::string dst_ip,
                   uint8_t protocal, int payload_len);

void InitUdpHeader(struct udphdr* udp_header, int src_port, int dst_port, int payload_len);

uint16_t checksum(uint16_t *addr, int len);

uint16_t udp_checksum(struct ip* iphdr, struct udphdr* udphdr, uint8_t *payload, int payloadlen);

void Hexdump(uint8_t* data, int data_len);

void PrintEthernetHeader(struct ether_header* ether_header);
void PrintIpHeader(struct ip *ip_header);
void PrintUdpHeader(struct udphdr* udp_header);
#endif

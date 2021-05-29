#include "utils.h"

/* Init IP header */
void InitIp4Header(struct ip* ip_header, std::string src_ip,
                   std::string dst_ip, uint8_t protocal, int payload_len)
{
    ip_header->ip_hl = IP4_HDRLEN / sizeof(u_int32_t);
    ip_header->ip_v  = 4;
    ip_header->ip_tos = 0;
    ip_header->ip_len = htons(IP4_HDRLEN + UDP_HDRLEN + payload_len);
    ip_header->ip_id = htons(0);

    int ip_flags[] = {0, 0, 0, 0};
    ip_header->ip_off = htons(
                            (ip_flags[0] << 15) +
                            (ip_flags[1] << 14) +
                            (ip_flags[2] << 13) +
                            (ip_flags[3] << 12)
                        );
    ip_header->ip_ttl = 255;
    ip_header->ip_p = protocal;
    TEST(inet_pton(AF_INET, src_ip.c_str(), &(ip_header->ip_src)) == 1);
    TEST(inet_pton(AF_INET, dst_ip.c_str(), &(ip_header->ip_dst)) == 1);

    ip_header->ip_sum = 0;
}

/* Init UDP header */
void InitUdpHeader(struct udphdr* udp_header, int src_port, int dst_port, int payload_len)
{
    udp_header->source = htons(src_port);
    udp_header->dest = htons(dst_port);
    udp_header->len = htons(UDP_HDRLEN + payload_len);

}


// Computing the internet checksum (RFC 1071)->
// Note that the internet checksum is not guaranteed to preclude collisions->
uint16_t checksum(uint16_t *addr, int len)
{

    int count = len;
    uint32_t sum = 0;
    uint16_t answer = 0;

    // Sum up 2-byte values until none or only one byte left->
    while (count > 1) {
        sum += *(addr++);
        count -= 2;
    }

    // Add left-over byte, if any->
    if (count > 0) {
        sum += *(uint8_t *)addr;
    }

    // Fold 32-bit sum into 16 bits; we lose information by doing this,
    // increasing the chances of a collision->
    // sum = (lower 16 bits) + (upper 16 bits shifted right 16 bits)
    while (sum >> 16) {
        sum = (sum & 0xffff) + (sum >> 16);
    }

    // Checksum is one's compliment of sum->
    answer = ~sum;

    return (answer);
}

// Build IPv4 UDP pseudo-header and call checksum function->
uint16_t udp_checksum(struct ip* iphdr, struct udphdr* udphdr, uint8_t *payload, int payloadlen)
{

    char buf[IP_MAXPACKET];
    char *ptr;
    int chksumlen = 0;
    int i;

    ptr = &buf[0]; // ptr points to beginning of buffer buf

    // Copy source IP address into buf (32 bits)
    memcpy(ptr, &iphdr->ip_src.s_addr, sizeof(iphdr->ip_src.s_addr));
    ptr += sizeof(iphdr->ip_src.s_addr);
    chksumlen += sizeof(iphdr->ip_src.s_addr);

    // Copy destination IP address into buf (32 bits)
    memcpy(ptr, &iphdr->ip_dst.s_addr, sizeof(iphdr->ip_dst.s_addr));
    ptr += sizeof(iphdr->ip_dst.s_addr);
    chksumlen += sizeof(iphdr->ip_dst.s_addr);

    // Copy zero field to buf (8 bits)
    *ptr = 0;
    ptr++;
    chksumlen += 1;

    // Copy transport layer protocol to buf (8 bits)
    memcpy(ptr, &iphdr->ip_p, sizeof(iphdr->ip_p));
    ptr += sizeof(iphdr->ip_p);
    chksumlen += sizeof(iphdr->ip_p);

    // Copy UDP length to buf (16 bits)
    memcpy(ptr, &udphdr->len, sizeof(udphdr->len));
    ptr += sizeof(udphdr->len);
    chksumlen += sizeof(udphdr->len);

    // Copy UDP source port to buf (16 bits)
    memcpy(ptr, &udphdr->source, sizeof(udphdr->source));
    ptr += sizeof(udphdr->source);
    chksumlen += sizeof(udphdr->source);

    // Copy UDP destination port to buf (16 bits)
    memcpy(ptr, &udphdr->dest, sizeof(udphdr->dest));
    ptr += sizeof(udphdr->dest);
    chksumlen += sizeof(udphdr->dest);

    // Copy UDP length again to buf (16 bits)
    memcpy(ptr, &udphdr->len, sizeof(udphdr->len));
    ptr += sizeof(udphdr->len);
    chksumlen += sizeof(udphdr->len);

    // Copy UDP checksum to buf (16 bits)
    // Zero, since we don't know it yet
    *ptr = 0;
    ptr++;
    *ptr = 0;
    ptr++;
    chksumlen += 2;

    // Copy payload to buf
    memcpy(ptr, payload, payloadlen);
    ptr += payloadlen;
    chksumlen += payloadlen;

    // Pad to the next 16-bit boundary
    for (i = 0; i < payloadlen % 2; i++, ptr++) {
        *ptr = 0;
        ptr++;
        chksumlen++;
    }

    return checksum((uint16_t *)buf, chksumlen);
}

void Hexdump(uint8_t* data, int data_len)
{
    printf("\n");
    for (int i = 0; i < data_len ; i++) {
        switch (i % 16) {
        case 0:
            printf("0x%.4x  ", i);
            printf("%.2x", data[i]);
            break;
        case 15:
            printf("%.2x\n", data[i]);
            break;
        case 1:
            printf("%.2x ", data[i]);
            break;

        default:
            // cout << (i & 15) << " ";
            (i & 1) ? printf("%.2x ", data[i]) : printf("%.2x", data[i]);
            break;
        }
    }
    printf("\n");
}

void PrintEthernetHeader(struct ether_header* ether_header)
{

    printf("\n");
    printf("Ethernet Header\n");
    printf("   |-Destination Address : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n",
           ether_header->ether_dhost[0], ether_header->ether_dhost[1],
           ether_header->ether_dhost[2], ether_header->ether_dhost[3],
           ether_header->ether_dhost[4], ether_header->ether_dhost[5]);
    printf("   |-Source Address      : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n",
           ether_header->ether_shost[0], ether_header->ether_shost[1],
           ether_header->ether_shost[2], ether_header->ether_shost[3],
           ether_header->ether_shost[4], ether_header->ether_shost[5]);
    printf("   |-Protocol            : %u \n", (unsigned short)ether_header->ether_type);
}


void PrintIpHeader(struct ip *ip_header)
{

    int iphdrlen = ip_header->ip_hl * 4;

    printf("\n");
    printf("IP Header\n");
    printf("   |-IP Version        : %d\n", (unsigned int)ip_header->ip_v);
    printf("   |-IP Header Length  : %d DWORDS or %d Bytes\n",
           (unsigned int)ip_header->ip_hl, ((unsigned int)(ip_header->ip_hl)) * 4);
    printf("   |-Type Of Service   : %d\n", (unsigned int)ip_header->ip_tos);
    printf("   |-IP Total Length   : %d  Bytes(Size of Packet)\n",
           ntohs(ip_header->ip_len));
    printf("   |-Identification    : %d\n",
           ntohs(ip_header->ip_id));
    printf("   |-TTL      : %d\n", (unsigned int)ip_header->ip_ttl);
    printf("   |-Protocol : %d\n", (unsigned int)ip_header->ip_p);
    printf("   |-Checksum : %d\n", ntohs(ip_header->ip_sum));
    printf("   |-Source IP        : %s\n", inet_ntoa(ip_header->ip_src));
    printf("   |-Destination IP   : %s\n", inet_ntoa(ip_header->ip_dst));
}


void PrintUdpHeader(struct udphdr* udp_header)
{
    printf("\nUDP Header\n");
    printf("   |-Source Port      : %d\n", ntohs(udp_header->source));
    printf("   |-Destination Port : %d\n", ntohs(udp_header->dest));
    printf("   |-UDP Length       : %d\n", ntohs(udp_header->len));
    printf("   |-UDP Checksum     : %d\n", ntohs(udp_header->check));
}

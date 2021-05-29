#include "utils.h"


int main(int argc, char* argv[])
{
    u_int8_t buffer[PACKETSIZE];
    struct ether_header *ether_header = (struct ether_header*)buffer;
    struct ip* ip_header = (struct ip*)(buffer + ETH_HDRLEN);
    struct udphdr* udp_header = (struct udphdr*)(buffer + ETH_HDRLEN + IP4_HDRLEN);
    uint8_t *payload = (buffer + ETH_HDRLEN + IP4_HDRLEN +  UDP_HDRLEN);
    int sd;
    struct sockaddr_ll device;
    uint8_t src_mac[6];
    uint8_t dst_mac[6];


    // Socket Descriptor
    TRY((sd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))));

    // Set interface and get some info
    char interface[IFNAMSIZ];
    strcpy(interface, "eth0");

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    memcpy(ifr.ifr_name, interface, sizeof(ifr.ifr_name));
    TRY(ioctl(sd, SIOCGIFHWADDR, &ifr));


    // Get source mac
    memcpy(src_mac, ifr.ifr_hwaddr.sa_data, 6);

    memset(&device, 0, sizeof(device));
    TRY((device.sll_ifindex = if_nametoindex(interface)));

    // Set destination Mac address
    dst_mac[0] = 0x00;
    dst_mac[1] = 0x0c;
    dst_mac[2] = 0x29;
    dst_mac[3] = 0x2e;
    dst_mac[4] = 0x69;
    dst_mac[5] = 0x57;

    // UDP_data
    payload[0] = 'T';
    payload[1] = 'E';
    payload[2] = 'S';
    payload[3] = 'T';
    int payload_len = 4;

    // Fill out sockaddr_ll
    device.sll_family = AF_PACKET;
    memcpy(device.sll_addr, src_mac, 6 * sizeof(uint8_t));
    device.sll_halen = 6;

    // Init basic header info
    memcpy(ether_header->ether_shost, src_mac, 6 * sizeof(uint8_t));
    memcpy(ether_header->ether_dhost, dst_mac, 6 * sizeof(uint8_t));
    ether_header->ether_type = htons(ETH_P_IP);

    InitIp4Header(ip_header, "192.168.0.136", "192.168.0.103", IPPROTO_UDP, 4);
    InitUdpHeader(udp_header, 1234, 4321, 4);

    // Calculate checksum
    ip_header->ip_sum = checksum((uint16_t*)ip_header, IP4_HDRLEN);
    udp_header->check = udp_checksum(ip_header, udp_header, payload, 4);

    int frame_length = payload_len + ETH_HDRLEN + UDP_HDRLEN + IP4_HDRLEN;

    PrintEthernetHeader(ether_header);
    PrintIpHeader(ip_header);
    PrintUdpHeader(udp_header);
    Hexdump(buffer, frame_length);

    int bytes;
    if ((bytes = sendto(sd, buffer, frame_length, 0, (struct sockaddr *)&device, sizeof(device))) <= 0) {
        perror("sendto() failed");
        exit(EXIT_FAILURE);
    }

}

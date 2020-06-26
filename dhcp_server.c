#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/ether.h>
#include "raw.h"

char ip_server[4] = {10, 0, 2, 15};
char ip_sniff[4] = {192, 168, 1, 10};

char this_mac[6];

// recv
#define PROTO_UDP	17
#define DST_PORT	67

char bcast_mac[6] =	{0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
char dst_mac[6] =	{0x00, 0x00, 0x00, 0x22, 0x22, 0x22};
char src_mac[6] =	{0x00, 0x00, 0x00, 0x33, 0x33, 0x33};

struct ifreq ifopts;
char ifName[IFNAMSIZ];
int sockfd, numbytes;
char *p;

union eth_buffer buffer_u;

//send
struct ifreq if_idx, if_mac, ifopts;
char ifName[IFNAMSIZ];
struct sockaddr_ll socket_address;
int sockfd, numbytes, size = 100;

uint32_t ipchksum(uint8_t *packet)
{
	uint32_t sum=0;
	uint16_t i;

	for(i = 0; i < 20; i += 2)
		sum += ((uint32_t)packet[i] << 8) | (uint32_t)packet[i + 1];
	while (sum & 0xffff0000)
		sum = (sum & 0xffff) + (sum >> 16);
	return sum;
}

int receive_dhcp() {
	while (1) {
		numbytes = recvfrom(sockfd, buffer_u.raw_data, ETH_LEN, 0, NULL, NULL);
		/* received a ipv4 package */
		if (buffer_u.cooked_data.ethernet.eth_type == ntohs(ETH_P_IP)){
			/* received a DHCP request */
			if (buffer_u.cooked_data.payload.ip.proto == PROTO_UDP && buffer_u.cooked_data.payload.udp.udphdr.dst_port == ntohs(DST_PORT))
			{
        memcpy(dst_mac, buffer_u.cooked_data.ethernet.src_addr, 6);
				printf("Recebido um DHCP request or discover\n");
				return 0;
			}
		}
	}
	return 1;
}

int dhcp_offer() {
	/* fill the Ethernet frame header */
	memcpy(buffer_u.cooked_data.ethernet.dst_addr, dst_mac, 6);
	memcpy(buffer_u.cooked_data.ethernet.src_addr, src_mac, 6);
	buffer_u.cooked_data.ethernet.eth_type = htons(ETH_P_IP);

	/* Fill IP header data. Fill all fields and a zeroed CRC field, then update the CRC! */
	buffer_u.cooked_data.payload.ip.ver = 0x45;
	buffer_u.cooked_data.payload.ip.tos = 0x00;
	buffer_u.cooked_data.payload.ip.len = htons(sizeof(struct ip_hdr) + sizeof(struct udp_hdr) + sizeof(struct dhcp_hdr));
	buffer_u.cooked_data.payload.ip.id = htons(0x00);
	buffer_u.cooked_data.payload.ip.off = htons(0x00);
	buffer_u.cooked_data.payload.ip.ttl = 50;
	buffer_u.cooked_data.payload.ip.proto = 0xff;
	buffer_u.cooked_data.payload.ip.sum = htons(0x0000);

  buffer_u.cooked_data.payload.ip.src[0] = ip_server[0];
	buffer_u.cooked_data.payload.ip.src[1] = ip_server[1];
	buffer_u.cooked_data.payload.ip.src[2] = ip_server[2];
	buffer_u.cooked_data.payload.ip.src[3] = ip_server[3];
	buffer_u.cooked_data.payload.ip.dst[0] = ip_sniff[0];
	buffer_u.cooked_data.payload.ip.dst[1] = ip_sniff[1];
	buffer_u.cooked_data.payload.ip.dst[2] = ip_sniff[2];
	buffer_u.cooked_data.payload.ip.dst[3] = ip_sniff[3];
	buffer_u.cooked_data.payload.ip.sum = htons((~ipchksum((uint8_t *)&buffer_u.cooked_data.payload.ip) & 0xffff));

  /* UDP */
  buffer_u.cooked_data.payload.udp.udphdr.src_port = htons(67);
	buffer_u.cooked_data.payload.udp.udphdr.dst_port = htons(68);
	buffer_u.cooked_data.payload.udp.udphdr.udp_len = htons(sizeof(struct udp_hdr));
	buffer_u.cooked_data.payload.udp.udphdr.udp_chksum = 0;

  /* DHCP */
  buffer_u.cooked_data.payload.dhcp.op = 2;
  buffer_u.cooked_data.payload.dhcp.htype = 1;
  buffer_u.cooked_data.payload.dhcp.hlen = 6;
  buffer_u.cooked_data.payload.dhcp.hops = 0;
  buffer_u.cooked_data.payload.dhcp.xid = 0x3903F326;
  buffer_u.cooked_data.payload.dhcp.secs = 0;
  buffer_u.cooked_data.payload.dhcp.flags = 0;
  buffer_u.cooked_data.payload.dhcp.ciaddr = 0;
  memcpy(buffer_u.cooked_data.payload.dhcp.yiaddr, ip_sniff, 4);
  memcpy(buffer_u.cooked_data.payload.dhcp.siaddr, ip_server, 4);
  buffer_u.cooked_data.payload.dhcp.giaddr = 0;

  /* magic cookie */
  buffer_u.cooked_data.payload.dhcp.magic[0] = 0x63;
	buffer_u.cooked_data.payload.dhcp.magic[1] = 0x82;
	buffer_u.cooked_data.payload.dhcp.magic[2] = 0x53;
	buffer_u.cooked_data.payload.dhcp.magic[3] = 0x63;

	/* Send it.. */
	memcpy(socket_address.sll_addr, dst_mac, 6);
	if (sendto(sockfd, buffer_u.raw_data, size + sizeof(struct eth_hdr) + sizeof(struct ip_hdr), 0, (struct sockaddr*)&socket_address, sizeof(struct sockaddr_ll)) < 0)
	{
		printf("Send failed\n");
		return 1;
	}
		

	return 0;
}

int main(int argc, char *argv[])
{
  if ((argc > 2) || (argc == 1)) {
    printf("Uso: ./dhcp <op:interface_name>\n");
    return 1;
  }

  /* Get interface name */
	if (argc > 1)
		strcpy(ifName, argv[1]);
	else
		strcpy(ifName, DEFAULT_IF);

  /* Open RAW socket */
	if ((sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) == -1)
		perror("socket");

  /* Set interface to promiscuous mode */
	strncpy(ifopts.ifr_name, ifName, IFNAMSIZ-1);
	ioctl(sockfd, SIOCGIFFLAGS, &ifopts);
	ifopts.ifr_flags |= IFF_PROMISC;
	ioctl(sockfd, SIOCSIFFLAGS, &ifopts);

	/* Get the index of the interface */
	memset(&if_idx, 0, sizeof(struct ifreq));
	strcpy(if_idx.ifr_name, ifName);
	if (ioctl(sockfd, SIOCGIFINDEX, &if_idx) < 0)
		perror("SIOCGIFINDEX");
	socket_address.sll_ifindex = if_idx.ifr_ifindex;
	socket_address.sll_halen = ETH_ALEN;

	/* Get the MAC address of the interface */
	memset(&if_mac, 0, sizeof(struct ifreq));
	strncpy(if_mac.ifr_name, ifName, IFNAMSIZ-1);
	if (ioctl(sockfd, SIOCGIFHWADDR, &if_mac) < 0)
		perror("SIOCGIFHWADDR");
	memcpy(this_mac, if_mac.ifr_hwaddr.sa_data, 6);

	/* procurar um DHCP DISCOVER */
	printf("1. Sniff na rede a procura de um DHCP OFFER\n");
	receive_dhcp();

	/* enviar um DHCP OFFER para o endereco sniff */
	printf("2. Montando um DHCP OFFER para o endereço sniff\n");
	dhcp_offer();

	/* receber um DHCP REQUEST */

	/* enviar um DHCP PACK */

  return 0;
}

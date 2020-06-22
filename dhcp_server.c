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

int main(int argc, char *argv[])
{
  if (argc > 3) {
    printf("Uso: ./dhcp_server <nome_da_interface> <ip_snoop>");
    return 1;
  }

  return 0;
}

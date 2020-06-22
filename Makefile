CC=gcc

all: dhcp

dhcp: dhcp_server.c
	$(CC) -o $@ $+

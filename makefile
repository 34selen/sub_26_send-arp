CC = gcc
CFLAGS = -Wall -O2
LDLIBS += -lpcap

all: send-arp

send-arp: send-arp.c util.c send-arp.h

clean:
	rm -f send-arp *.o

KERNELDIR = /usr/src/linux-2.4.18-14custom

include $(KERNELDIR)/.config

CFLAGS = -D__KERNEL__ -DMODULE -I$(KERNELDIR)/include -O -Wall

all: srandom.o

srandom.o: srandom.c srandom.h
	gcc -c -std=c99 $(CFLAGS) srandom.c -o srandom.o
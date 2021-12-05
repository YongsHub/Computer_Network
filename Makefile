CC = gcc
CFLAGS =
CLIBS =
CMDS = packetCapture

all : $(CMDS)

packetCapture : final.c
	$(CC) $^ -o $@ $(CLIBS) -lpthread -W

clean : 
	rm $(CMDS) core

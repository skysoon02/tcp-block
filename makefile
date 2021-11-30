LDLIBS=-lpcap

all: tcp-block

tcp-block: main.o tcphdr.o iphdr.o ethhdr.o ip.o mac.o
	$(LINK.cc) $^ $(LOADLIBES) $(LDLIBS) -o $@

clean:
	rm -f arp-spoof *.o

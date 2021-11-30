LDLIBS=-lpcap

all: tcp-block

arp-spoof: main.o tcphdr.o iphdr.o ethhdr.o ip.o mac.o
	$(LINK.cc) $^ $(LOADLIBES) $(LDLIBS) -o $@

clean:
	rm -f arp-spoof *.o

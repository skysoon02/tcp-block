#pragma once

#include <arpa/inet.h>

#pragma pack(push, 1)
struct TcpHdr final {
	uint16_t sPort;
	uint16_t dPort;
	uint32_t seq;
	uint32_t ack;
	uint16_t flag;
	uint16_t winSize;
	uint16_t checkSum;
	uint16_t urgPoint;
	
	Mac dmac_;
	Mac smac_;
	uint16_t type_;

	Mac dmac() { return dmac_; }
	Mac smac() { return smac_; }
	uint16_t type() { return ntohs(type_); }

	// Type(type_)
	enum: uint16_t {
		Ip4 = 0x0800,
		Arp = 0x0806,
		Ip6 = 0x86DD
	};
};
typedef TcpHdr *PTcpHdr;
#pragma pack(pop)

#pragma once

#include <arpa/inet.h>
#include "mac.h"

#pragma pack(push, 1)
struct EthHdr final {
	Mac dMac;
	Mac sMac;
	uint16_t type;

	//type
	enum: uint16_t {
		Ip4 = 0x0800,
		Arp = 0x0806,
		Ip6 = 0x86DD
	};
};
typedef EthHdr *PEthHdr;
#pragma pack(pop)

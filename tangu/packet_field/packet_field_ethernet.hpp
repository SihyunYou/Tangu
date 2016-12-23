//
// packet_field_ethernet.hpp
// Copyright © jynis2937, all rights reserved,
// This program is under the GNU Lesser General Public License.
//

#pragma once
#ifndef _PACKETFIELD_ETHERNET
#define _PACKETFIELD_ETHERNET

#include <net_manager\net_manager.hpp>

NAMESPACE_BEGIN(Packet)

#define _MIN_ETHERNETLEN		64
#define _MAX_ETHERNETLEN	1514
#pragma pack(push, 1)
/*
* @brief    packet_field section that supports Ethernet field
*/
typedef struct _ETHERNET_HEADER
{

	UINT64 Destination : 48;
	UINT64 Source : 48;

	enum class EthernetType
	{
		XEROX_NS_IDP = 0x0600,
		IPV4 = 0x0800,
		X75 = 0x0801,
		NBS = 0x0802,
		ECMA = 0x0803,
		CHAOSNET = 0x0804,

		ARP = 0x0806,
		XNS = 0x0807,
		FRAMERELAY_ARP = 0x0808,
		DRARP = 0x8035,
		AARP = 0x80F3,

		VLAN = 0x8100,
	};
	UINT16 Type;

} ETHERNET_HEADER, *PETHERNET_HEADER, &RETHERNET_HEADER;
#pragma pack(pop)

NAMESPACE_END /* Packet */

#endif /* packet_field_ethernet */
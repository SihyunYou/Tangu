#pragma once
#ifndef _PACKETFIELD_ARP
#define _PACKETFIELD_ARP

#include "packet_field_ethernet.hpp"

NAMESPACE_BEGIN(Packet)

typedef struct ARP_ARCHITECT
{
	enum class HWType
	{
		ETHERNET = 0x0001,
		EXPERIMENTAL_ETHERNET,
		AMATEUR_RADIO_AX_25,
		PROTEON_PRONET_TOKEN_RING,
		CHAOS,
		IEEE802_NETWORKS,
		ARCNET,
		HYPERCHANNEL,
		LANSTAR,
		AUTONET_SHORT_ADDRESS,
		LOCALTALK,
		LOCALNET
	};
	USHORT HardwareType;	// Hardware Type
	USHORT ProtocolType;		// Protocol Type
	UCHAR	 MACLen;				// Hardware Address Length
	UCHAR IPLen;					// Protocol Address Length
	
	enum class Opcode
	{
		REQUEST = 0x01, REPLY = 0x02
	};
	USHORT Operation;			// Operation Code

	UCHAR	 SenderMAC[6];		// Sender Hardware Address
	UCHAR	 SenderIP[4];			// Sender Protocol Address
	UCHAR	 TargetMAC[6];		// Target Hardware Address
	UCHAR TargetIP[4];			// Target Protocol Address
} ARP_ARCH, *PARP_ARCH;

typedef class __ARP
{
public:
	ETHERNET_HEADER EthernetHeader;
	ARP_ARCH ARPFrame;

	BYTE _Msg[_MIN_ETHERNETLEN];
	Net::L3 _Rsrc;

public:
	__ARP::__ARP(void);

public:
	void __ARP::GetARP(ARP_ARCHITECT::Opcode);
} ARP, *PARP;

NAMESPACE_END /* Packet */

#endif /* _PACKETFIELD_ARP */

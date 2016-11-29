//
// packet_field_arp.hpp
// Copyright © jynis2937, all rights reserved,
// This program is under the GNU Lesser General Public License.
//

#pragma once
#ifndef _PACKETFIELD_ARP
#define _PACKETFIELD_ARP

#include <packet_field\packet_field_ethernet.hpp>

NAMESPACE_BEGIN(Packet)

/*
* @brief    packet_field section that supports ARP field.
*/
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
	UINT16 HardwareType;	// Hardware Type
	UINT16 ProtocolType;		// Protocol Type
	UINT8 MACLen;				// Hardware Address Length
	UINT8 IPLen;					// Protocol Address Length
	
	enum class Opcode
	{
		REQUEST = 0x01, REPLY = 0x02
	};
	USHORT Operation;			// Operation Code
	
	UINT64 SenderMAC : 48;		// Sender Hardware Address
	UINT32 SenderIP : 32;			// Sender Protocol Address
	UINT64 TargetMAC : 48;		// Target Hardware Address
	UINT32 TargetIP : 32;			// Target Protocol Address

} ARP_ARCH, *PARP_ARCH;

/*
* @brief    A complete ARP frame field 
*/
typedef class TANGU_API __ARP
{
public:
	ETHERNET_HEADER EthernetHeader;
	ARP_ARCH ARPFrame;

	BYTE _Msg[_MIN_ETHERNETLEN];
	Net::L3ID _Rsrc;

public:
	/*
	* @brief    Constructor
	*          Initialize source address from local resources.
	*/
	__ARP::__ARP(void);

public:
	/*
	* @brief    Get ARP packet.
	* @param    Operation code 
	*/
	void __ARP::GetARP(ARP_ARCHITECT::Opcode);
} ARP, *PARP;

NAMESPACE_END /* Packet */

#endif /* _PACKETFIELD_ARP */
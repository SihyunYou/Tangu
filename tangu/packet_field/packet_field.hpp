//
// packet_field.hpp
// Copyright © jynis2937, all rights reserved,
// This program is under the GNU Lesser General Public License.
//

#pragma once
#ifndef _PACKETFIELD_H
#define _PACKETFIELD_H

#include <packet_field\packet_field_ethernet.hpp>
#include <packet_field\packet_field_arp.hpp>
#include <packet_field\packet_field_ip.hpp>
#include <packet_field\packet_field_icmp.hpp>
#include <packet_field\packet_field_tcp.hpp>

NAMESPACE_BEGIN(Packet)

class TANGU_API Utility
{
public:
	unsigned __int64 static __forceinline Utility::Trace(LPCBYTE, UINT);
	void static Utility::CustomPermutate(string&, LPCSTR, ...);

	unsigned __int16 static Utility::IPCheckSum(PIP_HEADER);
	unsigned __int16 static Utility::ICMPCheckSum(PICMP_ARCH);
	unsigned __int16 static Utility::TCPCheckSum(PIP_HEADER, PTCP_HEADER);
};

NAMESPACE_BEGIN(Hton)

class TANGU_API Utility
{
#define hton16(x) htons(x)
#define hton32(x) htonl(x)
#pragma warning(disable : 4244)
#define hton48(x) \
	((x & 0x0000FF0000000000) >> (CHAR_BIT * 5)) | \
	((x & 0x000000FF00000000) >> (CHAR_BIT * 3)) | \
	((x & 0x00000000FF000000) >> (CHAR_BIT * 1)) | \
	((x & 0x0000000000FF0000) << (CHAR_BIT * 1)) | \
	((x & 0x000000000000FF00) << (CHAR_BIT * 3)) | \
	((x & 0x00000000000000FF) << (CHAR_BIT * 5))
#define hton64(x) \
	((x & 0xFF00000000000000) >> (CHAR_BIT * 7)) | \
	((x & 0x00FF000000000000) >> (CHAR_BIT * 5)) | \
	((x & 0x0000FF0000000000) >> (CHAR_BIT * 3)) | \
	((x & 0x000000FF00000000) >> (CHAR_BIT * 1)) | \
	((x & 0x00000000FF000000) << (CHAR_BIT * 1)) | \
	((x & 0x0000000000FF0000) << (CHAR_BIT * 3)) | \
	((x & 0x000000000000FF00) << (CHAR_BIT * 5)) | \
	((x & 0x00000000000000FF) << (CHAR_BIT * 7))

public:
	void static Utility::ReorderEthernetHeader(ETHERNET_HEADER& _EthHdr)
	{
		_EthHdr.Destination = hton48(_EthHdr.Destination);
		_EthHdr.Source = hton48(_EthHdr.Source);
		_EthHdr.Type = hton16(_EthHdr.Type);
	}
	void static Utility::ReorderARPArch(ARP_ARCHITECT& _ARPArch)
	{
		_ARPArch.HardwareType = hton16(_ARPArch.HardwareType);
		_ARPArch.ProtocolType = hton16(_ARPArch.ProtocolType);	
		_ARPArch.SenderMAC = hton48(_ARPArch.SenderMAC);
		_ARPArch.SenderIP = hton32(_ARPArch.SenderIP);
		_ARPArch.TargetMAC = hton48(_ARPArch.TargetMAC);
		_ARPArch.TargetIP = hton48(_ARPArch.TargetIP);
	}
};

NAMESPACE_END
NAMESPACE_END

typedef Packet::Utility PktUtil;
typedef Packet::Hton::Utility HtonUtil;

#define SIZ_ETHERNET sizeof(ETHERNET_HEADER)
#define SIZ_ARP SIZ_ETHERNET + sizeof(ARP_ARCH)
#define SIZ_IP SIZ_ETHERNET + sizeof(IP_HEADER)

#endif /* _PACKETFIELD_H */
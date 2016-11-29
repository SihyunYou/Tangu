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

/*
* @brief    The utility APIs for a packet field on each layer.
*/
class TANGU_API Utility
{
public:
	/*
	* @brief    Read data in the specified length with converting network packet 
	*           order to host packet order.
	* @param	    Packet data
	* @param    Length
	* @return   Packet data within the specified field
	*/
	unsigned __int64 static __forceinline Utility::Trace(LPCBYTE, UINT);
	/*
	* @brief    Append string with formatted data (printf series).
	* @param	    STL string instance reference
	* @param    Format string for variadic arguments
	* @param    a value which is expected to be used to replace a format 
	*           specifier in the format string. 
	*/
	void static Utility::CustomPermutate(string&, LPCSTR, ...);

	/*
	* @param	    Tangu-defined IPv4 header pointer
	* @return   Check sum of IPv4 header.
	*/
	unsigned __int16 static Utility::IPCheckSum(PIP_HEADER);
	/*
	* @param	    Tangu-defined ICMP header pointer
	* @return   Check sum of ICMP header.
	*/
	unsigned __int16 static Utility::ICMPCheckSum(PICMP_ARCH);
	/*
	* @param	    Tangu-defined TCP header pointer
	* @return   Check sum of TCP header.
	*/
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
	/*
	* @brief    Convert host packet order to network packet order in Ethernet header.  
	* @param	    Tangu-defined Ethernet header.
	*/
	void static Utility::ReorderEthernetHeader(ETHERNET_HEADER& _EthHdr)
	{
		_EthHdr.Destination = hton48(_EthHdr.Destination);
		_EthHdr.Source = hton48(_EthHdr.Source);
		_EthHdr.Type = hton16(_EthHdr.Type);
	}
	/*
	* @brief    Convert host packet order to network packet order in ARP structure.
	* @param	    Tangu-defined ARP structure.
	*/
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
#define SIZ_ICMP SIZ_IP + sizeof(ICMP_ARCH)
#define SIZ_TCP SIZ_IP + sizeof(TCP_HEADER)

#endif /* _PACKETFIELD_H */
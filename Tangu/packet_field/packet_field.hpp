#pragma once
#ifndef _PACKETFIELD_H
#define _PACKETFIELD_H

#include "packet_field_ethernet.hpp"
#include "packet_field_arp.hpp"
#include "packet_field_ip.hpp"
#include "packet_field_icmp.hpp"
#include "packet_field_tcp.hpp"

NAMESPACE_BEGIN(Packet)

__forceinline unsigned __int16 IPCheckSum(PIP_HEADER);
__forceinline unsigned __int16 ICMPCheckSum(PICMP_ARCH);
__forceinline unsigned __int16 TCPChecksum(PIP_HEADER, PTCP_HEADER);

class Utility
{
public:
	static UINT Utility::Trace(const LPBYTE, UINT);
	static void Utility::CustomPermutate(string&, LPCSTR, ...);
};

NAMESPACE_END

typedef Packet::Utility PktUtil;

#endif /* _PACKETFIELD_H */
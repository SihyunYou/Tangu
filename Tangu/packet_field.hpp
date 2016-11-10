#pragma once
#ifndef _PACKETFIELD_H
#define _PACKETFIELD_H

#include "packet_field_ethernet.hpp"
#include "packet_field_arp.hpp"
#include "packet_field_ip.hpp"
#include "packet_field_icmp.hpp"
#include "packet_field_tcp.hpp"

namespace Packet
{
	class Utility
	{
	public:
		static CHAR						_Buf[0x20];
		static DWORD					_Dec;

	public:
		static UINT Utility::Trace(const BYTE*, UINT);
		static void Utility::CustomPermutate(string&, const CHAR*, ...);
	};
}

#endif /* _PACKETFIELD_H */
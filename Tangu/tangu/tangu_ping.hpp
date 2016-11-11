#pragma once
#ifndef _TANGU_PING
#define _TANGU_PING

#include "tangu_analyzer.hpp"

class PacketGrouper : protected NetInfo
{
private:
	Packet::ICMP _ICMPPacket;
	
public:
	PacketGrouper::PacketGrouper(pcap_t** Interface, Net::IPInfo Target)
		: NetInfo(Interface)
	{
		Net::PIPAdapterInfo AddressInfo = Net::IPAdapterInfo::GetInstance();
		Net::PIPNetTableInfo NetTableInfo = Net::IPNetTableInfo::GetInstance();

		_ICMPPacket._Rsrc.ISrc = Net::Utility::GetIPAddress(AddressInfo);
		_ICMPPacket._Rsrc.IDst = Target;
		_ICMPPacket._Rsrc.MSrc = Net::Utility::GetMACAddress(AddressInfo);
		_ICMPPacket._Rsrc.MDst = Net::Utility::GetGatewayMACAddress(NetTableInfo);
	}
	void PacketGrouper::Ping(Packet::ICMP_ARCH::ICMPType Type)
	{
		_ICMPPacket.GetICMP(Type);
		pcap_sendpacket(*_Interface, _ICMPPacket._Msg, 
			sizeof(Packet::ETHERNET_HEADER) + sizeof(Packet::IP_HEADER) + sizeof(Packet::ICMP_ARCH));
	}
};

#endif /* _TANGU_PING */
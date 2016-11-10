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

		_ICMPPacket._Rsrc.IDst = Target;
		_ARPFrame._Rsrc.ISrc = _ICMPPacket._Rsrc.ISrc = Net::Utility::GetIPAddress(AddressInfo);
		_ARPFrame._Rsrc.MSrc = _ICMPPacket._Rsrc.MSrc = Net::Utility::GetMACAddress(AddressInfo);

		_ARPFrame._Rsrc.IDst = Net::Utility::GetGatewayIPAddress(AddressInfo);
		_ARPFrame._Rsrc.MDst = "FF-FF-FF-FF-FF-FF";
		_ICMPPacket._Rsrc.MDst = _ARPFrame._Rsrc.MDst = GetMACAddress(_ARPFrame._Rsrc.IDst, 30.0).Source;
	}
	void PacketGrouper::Ping(Packet::ICMP_ARCH::ICMPType Type)
	{
		_ICMPPacket.GetICMP(Type);
		pcap_sendpacket(*_Interface, _ICMPPacket._Msg, 
			sizeof(Packet::ETHERNET_HEADER) + sizeof(Packet::IP_HEADER) + sizeof(Packet::ICMP_ARCH));
	}
};

#endif /* _TANGU_PING */
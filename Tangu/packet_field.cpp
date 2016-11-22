#pragma once
#include <packet_field\packet_field.hpp>

namespace Packet /* packet_field.hpp */
{
	__forceinline unsigned __int16 IPCheckSum(PIP_HEADER IPHdrBuf)
	{
		unsigned __int8* Buf = (unsigned __int8*)IPHdrBuf;
		unsigned __int32 Sum{ 0 };

		IPHdrBuf->Checksum = 0;
		for (int i = 0; i < sizeof(IP_HEADER); i = i + 2)
		{
			Sum += ((Buf[i] << 8) + Buf[i + 1]);
		}

		Sum = (Sum >> 16) + (Sum & 0xFFFF);
		Sum += (Sum >> 16);

		return  ~((unsigned __int16)Sum & 0xFFFF);
	}
	__forceinline unsigned __int16 ICMPCheckSum(PICMP_ARCH ICMPHdrBuf)
	{
		unsigned __int8* Buf = (unsigned __int8*)ICMPHdrBuf;
		unsigned __int32 Sum{ 0 };

		ICMPHdrBuf->Checksum = 0;
		for (int i = 0; i < sizeof(ICMP_ARCH); i = i + 2)
		{
			Sum += ((Buf[i] << 8) + Buf[i + 1]);
		}

		Sum = (Sum >> 16) + (Sum & 0xFFFF);
		Sum += (Sum >> 16);

		ICMPHdrBuf->Checksum = ~((unsigned __int16)Sum & 0xFFFF);
	}
	__forceinline unsigned __int16 TCPChecksum(PIP_HEADER IPHdrBuf, PTCP_HEADER TCPHdrBuf)
	{
		unsigned __int16* Buf{ (unsigned short *)TCPHdrBuf };
		unsigned short PayloadLen{ ntohs(IPHdrBuf->TotalLength) - sizeof(IP_HEADER) };
		unsigned __int32 Sum{ 0 };

		TCPHdrBuf->Checksum = 0;
		for (int i = 0; i < PayloadLen >> 1; i++)
		{
			Sum += Buf[i];
		}

		if (PayloadLen & 2)
		{
			Sum += Buf[PayloadLen] & 0x00FF;
		}

		for (int i = 0; i < 4; ++i)
		{
			Sum += ((unsigned __int16*)(&IPHdrBuf->Source))[i];
		}

		Sum += htons(UCast(16)(IP_HEADER::IPProto::TCP));
		Sum += htons(PayloadLen);

		Sum = (Sum >> 16) + (Sum & 0xFFFF);
		Sum += (Sum >> 16);

		TCPHdrBuf->Checksum = ~((unsigned __int16)Sum & 0xFFFF);
	}
}

namespace Packet /* packet_field.hpp # class Utility */
{
	UINT Utility::Trace(const LPBYTE Data, UINT Length)
	{
		if (Length > sizeof(long))
		{
			return -1;
		}
		else
		{
			CHAR Buf[0x20] = { 0 };
			DWORD Dec = 0;
			for (int Byte = Length - 1; Byte >= 0; --Byte)
			{
				sprintf_s(Buf, "%i", Data[Length - Byte - 1]);
				Dec += (atoi(Buf) << (Byte * CHAR_BIT));
			}

			return Dec;
		}
	}
	void Utility::CustomPermutate(string& Content, LPCSTR Format, ...)
	{
		CHAR FormatBuf[FORMAT_MESSAGE_ALLOCATE_BUFFER];
		va_list Marker;

		va_start(Marker, Format);
		vsprintf_s(FormatBuf, Format, Marker);

		Content += FormatBuf;
	}
}

namespace Packet /* packet_field_arp.hpp # class __ARP */
{
	__ARP::__ARP(void)
	{
		Net::PIPAdapterInfo AddressInfo = Net::IPAdapterInfo::GetInstance();

		_Rsrc.ISrc = NetUtil::GetIPAddress(AddressInfo);
		_Rsrc.MSrc = NetUtil::GetMACAddress(AddressInfo);
	}

	void __ARP::GetARP(ARP_ARCHITECT::Opcode Operation)
	{
		if (Operation == ARP_ARCH::Opcode::REQUEST)
		{
			_Rsrc.MDst = "FF-FF-FF-FF-FF-FF";
		}
		memcpy(EthernetHeader.Destination, *_Rsrc.MDst, SIZ_HARDWARE);
		memcpy(EthernetHeader.Source, *_Rsrc.MSrc, SIZ_HARDWARE);
		EthernetHeader.Type = htons(UCast(16)(ETHERNET_HEADER::EthernetType::ARP));
		
		ARPFrame.HardwareType = htons(UCast(16)(ARP_ARCH::HWType::ETHERNET));
		ARPFrame.ProtocolType = htons(UCast(16)(ETHERNET_HEADER::EthernetType::IPV4));
		ARPFrame.MACLen = SIZ_HARDWARE;
		ARPFrame.IPLen = SIZ_PROTOCOL;
		ARPFrame.Operation = htons(UCast(16)(Operation));

		Net::PIPAdapterInfo AddressInfo = Net::IPAdapterInfo::GetInstance();

		_Rsrc.ISrc = Net::Utility::GetIPAddress(AddressInfo);
		_Rsrc.MSrc = Net::Utility::GetMACAddress(AddressInfo);
		_Rsrc.IDst = Net::Utility::GetGatewayIPAddress(AddressInfo);
		_Rsrc.MDst = "FF-FF-FF-FF-FF-FF";

		memcpy(ARPFrame.SenderMAC, *_Rsrc.MSrc, SIZ_HARDWARE);
		memcpy(ARPFrame.SenderIP, *_Rsrc.ISrc, SIZ_PROTOCOL);
		memcpy(ARPFrame.TargetMAC, *_Rsrc.MDst, SIZ_HARDWARE);
		memcpy(ARPFrame.TargetIP, *_Rsrc.IDst, SIZ_PROTOCOL);

		memcpy(_Msg, &EthernetHeader, sizeof(ETHERNET_HEADER));
		memcpy(_Msg + sizeof(ETHERNET_HEADER), &ARPFrame, sizeof(ARP_ARCH));
	}
}

namespace Packet /* packet_field_icmp.hpp # class __ICMP */
{
	__ICMP::__ICMP(void) 
		: Seed(RdFromHW()), Distributer(0, 0xFF00)
	{
		Net::IPAdapterInfo* AddressInfo = Net::IPAdapterInfo::GetInstance();

		_Rsrc.MSrc = Net::Utility::GetMACAddress(AddressInfo);
		_Rsrc.ISrc = Net::Utility::GetIPAddress(AddressInfo);

		Iden = static_cast<USHORT>(Distributer(Seed));
		Seq = static_cast<USHORT>(Distributer(Seed));
	}

	void __ICMP::GetICMP(ICMP_ARCH::ICMPType ControlMessage)
	{
		/* L2 { Data Link Layer } : Ethernet */
		memcpy(EthernetHeader.Destination, *this->_Rsrc.MDst, SIZ_HARDWARE);
		memcpy(EthernetHeader.Source, *this->_Rsrc.MSrc, SIZ_HARDWARE);
		EthernetHeader.Type = htons(UCast(16)(ETHERNET_HEADER::EthernetType::IPV4));

		/* L3 { Network Layer } : IP */
		IPHeader.IHL = IP_VERSION(IPPROTO_IPV4) | IP_HEADER_LENGTH(20);
		IPHeader.ServiceType = DSCP_CS_N(0) | ECN(0);
		IPHeader.TotalLength = htons(60);
		IPHeader.ldentification = htons(Iden++);
		IPHeader.Fragmention = htons(IP_FLAG(DONT_FRAGMENTS(0) | MORE_FRAGMENTS(0)));
		IPHeader.Protocol = UCast(8)(Packet::IP_HEADER::IPProto::ICMP);
		IPHeader.TTL = 128;
		memcpy(IPHeader.Source, &_Rsrc.ISrc, SIZ_PROTOCOL);
		memcpy(IPHeader.Destination, &_Rsrc.IDst, SIZ_PROTOCOL);
		IPHeader.Checksum = htons(Packet::IPCheckSum(&IPHeader));

		/* L3 { Network Layer } : ICMP */
		ICMPPacket.Type = UCast(8)(ControlMessage);
		ICMPPacket.Code = 0;
		ICMPPacket.Identifier = htons(1);
		ICMPPacket.Sequence = htons(Seq++);
		memcpy(ICMPPacket.Data, "abcdefghijkmnopqrstuvwabcdefghi", sizeof(ICMPPacket.Data));
		ICMPPacket.Checksum = htons(Packet::ICMPCheckSum(&IPHeader, &ICMPPacket));

		memcpy(_Msg, &EthernetHeader, sizeof(ETHERNET_HEADER));
		memcpy(_Msg + sizeof(ETHERNET_HEADER), &IPHeader, sizeof(Packet::IP_HEADER));
		memcpy(_Msg + sizeof(ETHERNET_HEADER) + sizeof(Packet::IP_HEADER), &ICMPPacket, sizeof(Packet::ICMP_ARCH));
	}

	__forceinline unsigned __int16 ICMPCheckSum(PIP_HEADER IPHeader, PICMP_ARCH UchkdICMP)
	{
		unsigned __int8* Buf = (unsigned __int8*)UchkdICMP;
		unsigned __int32 Sum{ 0 };

		UchkdICMP->Checksum = 0;
		for (int i = 0; i < sizeof(ICMP_ARCH); i = i + 2)
		{
			Sum += ((Buf[i] << 8) + Buf[i + 1]);
		}

		Sum = (Sum >> 16) + (Sum & 0xFFFF);
		Sum += (Sum >> 16);

		return ~((unsigned __int16)Sum & 0xFFFF);
	}
}

namespace Packet /* packet_field_ip.hpp */
{
	
}

namespace Packet /* packet_field_tcp.hpp */
{
	
}
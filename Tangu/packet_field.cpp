#pragma once
#include "packet_field.hpp"

namespace Packet /* _PacketField_H # class Utility */
{
	CHAR Utility::_Buf[0x20] = { 0 };
	DWORD Utility::_Dec = 0;

	UINT Utility::Trace(const BYTE* Data, UINT Length)
	{
		if (Length > sizeof(long))
		{
			return -1;
		}
		else
		{
			_Dec = 0;
			for (int Byte = Length - 1; Byte >= 0; --Byte)
			{
				sprintf_s(_Buf, "%i", Data[Length - Byte - 1]);
				_Dec += (atoi(_Buf) << (Byte * CHAR_BIT));
			}

			return _Dec;
		}
	}

	void Utility::CustomPermutate(string& Content, const CHAR* Format, ...)
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

		_Rsrc.ISrc = Net::Utility::GetIPAddress(AddressInfo);
		_Rsrc.MSrc = Net::Utility::GetMACAddress(AddressInfo);
	}

	void __ARP::GetARP(ARP_ARCH::Opcode Operation)
	{
		if (Operation == ARP_ARCH::Opcode::REQUEST)
		{
			_Rsrc.MDst = "FF-FF-FF-FF-FF-FF";
		}
		memcpy(_EthHead.Destination, *_Rsrc.MDst, SIZ_HARDWARE);
		memcpy(_EthHead.Source, *_Rsrc.MSrc, SIZ_HARDWARE);
		_EthHead.Type = htons(UCast(16)(ETHERNET_HEADER::EthernetType::ARP));
		
		_ARP.HardwareType = htons(UCast(16)(ARP_ARCH::HWType::ETHERNET));
		_ARP.ProtocolType = htons(UCast(16)(ETHERNET_HEADER::EthernetType::IPV4));
		_ARP.MACLen = SIZ_HARDWARE;
		_ARP.IPLen = SIZ_PROTOCOL;
		_ARP.Operation = htons(UCast(16)(Operation));

		Net::PIPAdapterInfo AddressInfo = Net::IPAdapterInfo::GetInstance();

		_Rsrc.ISrc = Net::Utility::GetIPAddress(AddressInfo);
		_Rsrc.MSrc = Net::Utility::GetMACAddress(AddressInfo);
		_Rsrc.IDst = Net::Utility::GetGatewayIPAddress(AddressInfo);
		_Rsrc.MDst = "FF-FF-FF-FF-FF-FF";

		memcpy(_ARP.SenderMAC, *_Rsrc.MSrc, SIZ_HARDWARE);
		memcpy(_ARP.SenderIP, *_Rsrc.ISrc, SIZ_PROTOCOL);
		memcpy(_ARP.TargetMAC, *_Rsrc.MDst, SIZ_HARDWARE);
		memcpy(_ARP.TargetIP, *_Rsrc.IDst, SIZ_PROTOCOL);

		memcpy(_Msg, &_EthHead, sizeof(ETHERNET_HEADER));
		memcpy(_Msg + sizeof(ETHERNET_HEADER), &_ARP, sizeof(ARP_ARCH));
	}
}

namespace Packet /* packet_field_icmp.hpp # class __ICMP */
{
	USHORT ICMPCheckSum(IP_HEADER* UchkdIP, ICMP_ARCH* UchkdICMP)
	{
		UINT Sum{ 0 };
		UchkdICMP->Checksum = 0;
		UchkdIP->Checksum = 0;

		USHORT* Short{ (USHORT*)UchkdICMP };
		for (UINT i = 0; i < sizeof(*UchkdICMP) / 2; i++)
		{
			Sum += *(Short + i);
		}

		Sum += (UchkdIP->SrcIP[0] << 8) + UchkdIP->SrcIP[1] + (UchkdIP->SrcIP[2] << 8) + UchkdIP->SrcIP[3];
		Sum += (UchkdIP->DestIP[0] << 8) + UchkdIP->DestIP[1] + (UchkdIP->DestIP[2] << 8) + UchkdIP->DestIP[3];
		Sum += UchkdIP->Protocol + sizeof(Packet::ICMP_ARCH);

		Sum = ((Sum & 0xFFFF0000) >> 16) + (Sum & 0x0000FFFF);
		Sum += (Sum & 0xFFFF0000) >> 16;
		Sum = ~Sum & 0x0000FFFF;

		return static_cast<USHORT>(Sum);
	}

	__ICMP::__ICMP(void) 
		: Seed(RdFromHW()), Distributer(0, 0xFF00)
	{
		Net::IPAdapterInfo* AddressInfo = Net::IPAdapterInfo::GetInstance();

		_Rsrc.MSrc = Net::Utility::GetMACAddress(AddressInfo);
		_Rsrc.ISrc = Net::Utility::GetIPAddress(AddressInfo);

		_Iden = static_cast<unsigned __int16>(Distributer(Seed));
		_Seq = static_cast<unsigned __int16>(Distributer(Seed));
	}

	USHORT __ICMP::CheckSum(void)
	{
		return _IPHead.Checksum;
	}

	void __ICMP::GetICMP(ICMP_ARCH::ICMPType ControlMessage)
	{
		/* L2 { Data Link Layer } : Ethernet */
		memcpy(_EthHead.Destination, *this->_Rsrc.MDst, SIZ_HARDWARE);
		memcpy(_EthHead.Source, *this->_Rsrc.MSrc, SIZ_HARDWARE);
		_EthHead.Type = htons(UCast(16)(ETHERNET_HEADER::EthernetType::IPV4));

		/* L3 { Network Layer } : IP */
		_IPHead.IHL = IP_VERSION(IPPROTO_IPV4) | IP_HEADER_LENGTH(20);
		_IPHead.ServiceType = DSCP_CS_N(0) | ECN(0);
		_IPHead.TotalLength = (UCHAR)htons(60);
		_IPHead.ldentification = htons(_Iden++);
		_IPHead.Fragmention = htons(IP_FLAG(DONT_FRAGMENTS(0) | MORE_FRAGMENTS(0)));
		_IPHead.Protocol = UCast(8)(Packet::IP_HEADER::IPProto::ICMP);
		_IPHead.TTL = 128;
		memcpy(_IPHead.SrcIP, &_Rsrc.ISrc, SIZ_PROTOCOL);
		memcpy(_IPHead.DestIP, &_Rsrc.IDst, SIZ_PROTOCOL);
		_IPHead.Checksum = htons(Packet::IPCheckSum(&_IPHead));

		/* L3 { Network Layer } : ICMP */
		_ICMP.Type = UCast(8)(ControlMessage);
		_ICMP.Code = 0;
		_ICMP.Identifier = htons(1);
		_ICMP.Sequence = htons(_Seq++);
		memcpy(_ICMP.Data, "abcdefghijkmnopqrstuvwabcdefghi", sizeof(_ICMP.Data));
		_ICMP.Checksum = htons(Packet::ICMPCheckSum(&_IPHead, &_ICMP));

		memcpy(_Msg, &_EthHead, sizeof(ETHERNET_HEADER));
		memcpy(_Msg + sizeof(ETHERNET_HEADER), &_IPHead, sizeof(Packet::IP_HEADER));
		memcpy(_Msg + sizeof(ETHERNET_HEADER) + sizeof(Packet::IP_HEADER), &_ICMP, sizeof(Packet::ICMP_ARCH));
	}
}

namespace Packet /* packet_field_ip.hpp */
{
	__forceinline USHORT IPCheckSum(Packet::PIP_HEADER UchkdIP)
	{
		UINT Sum{ 0 };
		UchkdIP->Checksum = 0;

		USHORT* Short{ (USHORT*)UchkdIP };
		for (UINT i = 0; i < sizeof(*UchkdIP) / 2; i++)
		{
			Sum += *(Short + i);
		}

		Sum = ((Sum & 0xFFFF0000) >> 16) + (Sum & 0x0000FFFF);
		Sum += (Sum & 0xFFFF0000) >> 16;
		Sum = ~Sum & 0x0000FFFF;

		return static_cast<USHORT>(Sum);
	}
}

namespace Packet /* packet_field_tcp.hpp */
{

}
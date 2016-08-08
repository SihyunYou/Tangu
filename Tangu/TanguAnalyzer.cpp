#pragma once

#include "TanguAnalyzer"

PacketInfo::PacketInfo() : 
	_DumpFiltered(""), _No(0)
{

}

Common::Common(pcap_t* Interface)
{
	_Interface = Interface;
}
ARPAnalyzer::ARPAnalyzer(pcap_t* Interface)
{
	_Interface = Interface;
}

const string& Common::PktParser(const byte* PacketData, PktBegin Stage)
{
	_DumpContent.clear();

	switch (Stage)
	{
	case PktBegin::LAYER_DATALINK:
		goto L2;

	case PktBegin::LAYER_NETWORK:
		goto L3;

	case PktBegin::LAYER_TRANSPORT:
		goto L4;
	}

	L2:	/* TCP/IP PktBegin 2 : Data Link PktBegin { Ethernet } */

	memcpy(_MyEthernet.Destination, PacketData, 6);
	memcpy(_MyEthernet.Source, PacketData + 6, 6);
	_MyEthernet.Type = Packet::Utility::Trace(PacketData + 12, 2);
	
	_DumpContent += "忙式式式式式式式式式式式式式式式式式式式式式式式式式式式式式式式式忖\n";

	Packet::Utility::CustomPermutate(_DumpContent, "弛   [Source MAC]   %02x:%02x:%02x:%02x:%02x:%02x                             弛\n",
		_MyEthernet.Source[0], _MyEthernet.Source[1], _MyEthernet.Source[2], _MyEthernet.Source[3], _MyEthernet.Source[4], _MyEthernet.Source[5]);

	Packet::Utility::CustomPermutate(_DumpContent, "弛[Destination MAC] %02x:%02x:%02x:%02x:%02x:%02x                             弛\n",
		_MyEthernet.Destination[0], _MyEthernet.Destination[1], _MyEthernet.Destination[2], _MyEthernet.Destination[3], _MyEthernet.Destination[4], _MyEthernet.Destination[5]);

	PacketData = PacketData + sizeof(EthernetHeader);
	_DumpContent += "弛      [Type]      ";
	switch (static_cast<EthernetHeader::EthernetType> (htons(_MyEthernet.Type)))
	{
	case EthernetHeader::EthernetType::ARP:
		_DumpContent += "Address Resolution Protocol (ARP) ";
		_ARPFrame.HardwareType = Packet::Utility::Trace(PacketData, 2);
		_ARPFrame.ProtocolType = Packet::Utility::Trace(PacketData + 2, 2);
		_ARPFrame.MACLen = Packet::Utility::Trace(PacketData + 4, 1);
		_ARPFrame.IPLen = Packet::Utility::Trace(PacketData + 5, 1);
		_ARPFrame.Operation = Packet::Utility::Trace(PacketData + 6, 2);
		
		memcpy(_ARPFrame.SenderMAC, PacketData + 8, SIZ_HARDWARE);
		memcpy(_ARPFrame.SenderIP, PacketData + 14, SIZ_PROTOCOL);
		memcpy(_ARPFrame.TargetMAC, PacketData + 18, SIZ_HARDWARE);
		memcpy(_ARPFrame.TargetIP, PacketData + 24, SIZ_PROTOCOL);

		goto Exit;

	case EthernetHeader::EthernetType::IPV4:
		_DumpContent += "Internet Protocol Version 4 (IPv4)";
		break;

	}
	Packet::Utility::CustomPermutate(_DumpContent, " (0x%04x)   弛\n", _MyEthernet.Type);
	_DumpContent += "戌式式式式式式式式式式式式式式式式式式式式式式式式式式式式式式式式戎\n";


	L3: /* TCP/IP PktBegin 3 : Internet PktBegin { IPv4 }*/

	_MyIP.IHL = Packet::Utility::Trace(PacketData, 1);
	_MyIP.ServiceType = Packet::Utility::Trace(PacketData + 1, 1);
	_MyIP.TotalLength = (Packet::Utility::Trace(PacketData + 2, 2));
	_MyIP.ldentification = (Packet::Utility::Trace(PacketData + 4, 2));

	_MyIP.Fragmention = (Packet::Utility::Trace(PacketData + 6, 2));
	_MyIP.TTL = Packet::Utility::Trace(PacketData + 8, 1);
	_MyIP.Protocol = Packet::Utility::Trace(PacketData + 9, 1);
	_MyIP.Checksum = (Packet::Utility::Trace(PacketData + 10, 2));
	memcpy(_MyIP.SrcIP, PacketData + 12, SIZ_PROTOCOL);
	memcpy(_MyIP.DestIP, PacketData + 16, SIZ_PROTOCOL);

	_DumpContent += "忙式式式式式式式式式式式式式式式式式式式式式式式式式式式式式式式式忖\n";
	Packet::Utility::CustomPermutate(_DumpContent, "弛   [Source  IP]   %3i.%3i.%3i.%3i                               弛\n",
		_MyIP.SrcIP[0], _MyIP.SrcIP[1], _MyIP.SrcIP[2], _MyIP.SrcIP[3]);
	Packet::Utility::CustomPermutate(_DumpContent, "弛 [Destination IP] %3i.%3i.%3i.%3i                               弛\n",
		_MyIP.DestIP[0], _MyIP.DestIP[1], _MyIP.DestIP[2], _MyIP.DestIP[3]);

	_DumpContent += "弛    [Protocol]    ";
	PacketData = PacketData + sizeof(IPHeader);
	switch (static_cast<IPHeader::IPProto>(_MyIP.Protocol))
	{
	case IPHeader::IPProto::ICMP:
		_DumpContent += "ICMP   ";

		_ICMPPacket.Type = Packet::Utility::Trace(PacketData, 1);
		_ICMPPacket.Code = Packet::Utility::Trace(PacketData + 1, 1);
		_ICMPPacket.Checksum = Packet::Utility::Trace(PacketData + 2, 2);
		_ICMPPacket.Identifier = Packet::Utility::Trace(PacketData + 4, 2);
		_ICMPPacket.Sequence = Packet::Utility::Trace(PacketData + 6, 2);

		memcpy(_ICMPPacket.Data, "abcdefghijklmnopqrstuvwabcdfghi", 32);
		
		goto Exit;

	case IPHeader::IPProto::TCP:
		_DumpContent += "Transmission Control Protocol (TCP)";
		break;

	case IPHeader::IPProto::USER_DATAGRAM:
		_DumpContent += "User Datagram Protocol (UDP)";
		goto Exit;

	default:
		_DumpContent += "UNKNOWN";
		goto Exit;
	}
	Packet::Utility::CustomPermutate(_DumpContent, " (0x%02x)                                弛\n", _MyIP.Protocol);
	_DumpContent += "戌式式式式式式式式式式式式式式式式式式式式式式式式式式式式式式式式戎\n";

	
	L4: /* TCP/IP PktBegin 4 : Transport PktBegin { TCP }*/

	_MyTCP.SrcPort = Packet::Utility::Trace(PacketData, 2);
	_MyTCP.DstPort = Packet::Utility::Trace(PacketData + 2, 2);
	_MyTCP.Sequence = Packet::Utility::Trace(PacketData + 4, 4);
	_MyTCP.Acknowledgemnet = Packet::Utility::Trace(PacketData + 8, 4);

	_MyTCP.FHL = Packet::Utility::Trace(PacketData + 12, 2);
	_MyTCP.WindowSize = Packet::Utility::Trace(PacketData + 14, 2);
	_MyTCP.Checksum = Packet::Utility::Trace(PacketData + 16, 2);
	_MyTCP.UrgentPointer = Packet::Utility::Trace(PacketData + 18, 2);

	_DumpContent += "忙式式式式式式式式式式式式式式式式式式式式式式式式式式式式式式式式忖\n";
	Packet::Utility::CustomPermutate(_DumpContent, "弛   [Source  Port]   %5i                               弛\n", _MyTCP.SrcPort);
	Packet::Utility::CustomPermutate(_DumpContent, "弛 [Destination Port] %5i                               弛\n", _MyTCP.DstPort);
	_DumpContent += "戌式式式式式式式式式式式式式式式式式式式式式式式式式式式式式式式式戎\n";

	PacketData = PacketData + (((_MyTCP.FHL >> 12) & 0x07) * 4); // sizeof(TCPHeader) + TCP Options' size 
	switch (static_cast<TCPHeader::Port>(_MyTCP.DstPort))
	{
	case TCPHeader::Port::HTTP:
		_HTTP = (char*)PacketData;
	}

	Exit: return _DumpContent;
}

const string& ARPAnalyzer::PktParser(const byte* PacketData, PktBegin Stage)
{
	_DumpContent.clear();
	_No = _No + 1;

	// Data Link PktBegin (L2)

	memcpy(_MyEthernet.Destination, PacketData, 6);
	memcpy(_MyEthernet.Source, PacketData + 6, 6);
	_MyEthernet.Type = Packet::Utility::Trace(PacketData + 12, 2);

	if (_MyEthernet.Type != UCast(16)(EthernetHeader::EthernetType::ARP))
	{
		return _DumpFiltered;
	}

	_DumpContent += "忙式式式式式式式式式式式式式式式式式式式式式式式式式式式式式式式式忖\n";

	Packet::Utility::CustomPermutate(_DumpContent, "弛   [Source MAC]   %02x:%02x:%02x:%02x:%02x:%02x                             弛\n",
		_MyEthernet.Source[0], _MyEthernet.Source[1], _MyEthernet.Source[2], _MyEthernet.Source[3], _MyEthernet.Source[4], _MyEthernet.Source[5]);

	Packet::Utility::CustomPermutate(_DumpContent, "弛[Destination MAC] %02x:%02x:%02x:%02x:%02x:%02x                             弛\n",
		_MyEthernet.Destination[0], _MyEthernet.Destination[1], _MyEthernet.Destination[2], _MyEthernet.Destination[3], _MyEthernet.Destination[4], _MyEthernet.Destination[5]);

	_DumpContent += "弛      [Type]      Address Resolution Protocol (ARP) ";
	Packet::Utility::CustomPermutate(_DumpContent, " (0x%04x)   弛\n", _MyEthernet.Type);
	_DumpContent += "戌式式式式式式式式式式式式式式式式式式式式式式式式式式式式式式式式戎\n";

	PacketData = PacketData + 14;

	memcpy(&_ARPFrame, PacketData, sizeof(ARPArchitect));

	_ARPFrame.HardwareType = htons(_ARPFrame.HardwareType);
	_ARPFrame.ProtocolType = htons(_ARPFrame.ProtocolType);
	_ARPFrame.Operation = htons(_ARPFrame.Operation);

	_DumpContent += "忙式式式式式式式式式式式式式式式式式式式式式式式式式式式式式式式式忖\n";
	Packet::Utility::CustomPermutate(_DumpContent, "弛 [Hardware  Type] %i                                             弛\n", _ARPFrame.HardwareType);
	Packet::Utility::CustomPermutate(_DumpContent, "弛 [Protocol  Type] %i                                          弛\n", _ARPFrame.ProtocolType);
	Packet::Utility::CustomPermutate(_DumpContent, "弛 [Hardware  Size] %i                                             弛\n", _ARPFrame.MACLen);
	Packet::Utility::CustomPermutate(_DumpContent, "弛 [Protocol  Size] %i                                             弛\n", _ARPFrame.IPLen);
	Packet::Utility::CustomPermutate(_DumpContent, "弛 [    Opcode    ] %i                                             弛\n", _ARPFrame.Operation);

	Packet::Utility::CustomPermutate(_DumpContent, "弛   [Sender MAC]   %02x:%02x:%02x:%02x:%02x:%02x                             弛\n",
		_ARPFrame.SenderMAC[0], _ARPFrame.SenderMAC[1], _ARPFrame.SenderMAC[2], _ARPFrame.SenderMAC[3], _ARPFrame.SenderMAC[4], _ARPFrame.SenderMAC[5]);
	Packet::Utility::CustomPermutate(_DumpContent, "弛   [Sender  IP]   %3i.%3i.%3i.%3i                               弛\n",
		_ARPFrame.SenderIP[0], _ARPFrame.SenderIP[1], _ARPFrame.SenderIP[2], _ARPFrame.SenderIP[3]);
	Packet::Utility::CustomPermutate(_DumpContent, "弛   [Target MAC]   %02x:%02x:%02x:%02x:%02x:%02x                             弛\n",
		_ARPFrame.TargetMAC[0], _ARPFrame.TargetMAC[1], _ARPFrame.TargetMAC[2], _ARPFrame.TargetMAC[3], _ARPFrame.TargetMAC[4], _ARPFrame.TargetMAC[5]);
	Packet::Utility::CustomPermutate(_DumpContent, "弛   [Sender  IP]   %3i.%3i.%3i.%3i                               弛\n",
		_ARPFrame.TargetIP[0], _ARPFrame.TargetIP[1], _ARPFrame.TargetIP[2], _ARPFrame.TargetIP[3]);
	
	_DumpContent += "戌式式式式式式式式式式式式式式式式式式式式式式式式式式式式式式式式戎\n";

	return _DumpContent;
}

const string& PacketInfo::DumpData(struct pcap_pkthdr* PacketHeader, const byte* PacketData, const unsigned int OutputLength)
{
	_DumpContent.clear();

	for (bpf_u_int32 i = 1; i <= PacketHeader->caplen; i += OutputLength)
	{
		for (bpf_u_int32 j = i; j < i + OutputLength; ++j)
		{
			Packet::Utility::CustomPermutate(_DumpContent, "%.2x ", PacketData[j - 1]);
		}
		_DumpContent += "  ";

		for (bpf_u_int32 j = i; j < i + OutputLength; ++j)
		{
			Packet::Utility::CustomPermutate(_DumpContent, "%c", !(0x20 < PacketData[j - 1] && PacketData[j - 1] < 0x7F) ? '.' : PacketData[j - 1]);
		}
		_DumpContent += "\n";
	}

	return _DumpContent;
}

PcapTool::PcapTool(void)
{
	
}

NetInfo::NetInfo(pcap_t** Interface)
{
	_Interface = Interface;
}

EthernetHeader NetInfo::GetMACAddress(Net::IPInfo& TargetSpoof, double TimeLimit)
{
	GenerateARP(ARPArch::Opcode::REQUEST);

	ARPAnalyzer	ARPPacketCapturer(*_Interface);
	_PcapAnalyzer = &ARPPacketCapturer;

	time_point<system_clock> Start{ system_clock::now() };

	while ((_Ret = pcap_next_ex(*_Interface, &_PacketHeader, &_PacketData)) >= 0)
	{
		if (!_Ret)
		{
			continue;
		}

		_PcapAnalyzer->PktParser(_PacketData, PktBegin::LAYER_DATALINK);
		if (ARPPacketCapturer._MyEthernet.Type == UCast(16)(EthernetHeader::EthernetType::ARP))
		{
			if (ARPPacketCapturer._ARPFrame.Operation != static_cast<unsigned __int16>(ARPArch::Opcode::REPLY))
			{
				continue;
			}
			if (!memcmp(ARPPacketCapturer._ARPFrame.SenderIP, *TargetSpoof, 4))
			{
				_CollectSuccess = true;
				break;
			}
		}

		if (duration<double>(system_clock::now() - Start).count() > TimeLimit)
		{
			_CollectSuccess = false;
			break;
		}
	}

	return ARPPacketCapturer._MyEthernet;
}

bool NetInfo::IsARPValid()
{
	return _CollectSuccess;
}
Net::MACInfo NetInfo::CollectNetworkInfo(Net::IPInfo& IPResource, double TimeLimit)
{
	return GetMACAddress(IPResource, TimeLimit).Source;
}

void NetInfo::GenerateARP(ARPArchitect::Opcode Operation)
{
	_ARPFrame.GetARP(Operation);
	pcap_sendpacket(*_Interface, _ARPFrame._Msg, sizeof(EthernetHeader) + sizeof(ARPArchitect));
}

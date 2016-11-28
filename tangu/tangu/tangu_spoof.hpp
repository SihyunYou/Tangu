#pragma once
#ifndef _TANGU_SPOOF
#define _TANGU_SPOOF

#include <tangu\tangu_analyzer.hpp>

class TANGU_API ARPSpoof : protected PCAPTOOL
{
public:
	Packet::ARP ARPFrame;
	pair<Net::MACInfo, Net::IPInfo> Gateway;
	bool SuccessReceived;
	INT Ret;

public:
	ARPSpoof::ARPSpoof(PPCAP*, Net::IPInfo);

protected:
	void ARPSpoof::GenerateARP(Packet::ARP_ARCH::Opcode);
	Net::MACInfo ARPSpoof::GetMACAddress(Net::IPInfo& TargetSpoof, double TimeLimit)
	{
		GenerateARP(Packet::ARP_ARCH::Opcode::REQUEST);

		PACKET_INFO ARPReplyHole;
		time_point<system_clock> Start{ system_clock::now() };
		
		do
		{
			Ret = pcap_next_ex(Interface, &PacketHeader, (const UCHAR**)&PacketData);
			if (0 == Ret)
			{
				continue;
			}

			ARPReplyHole.ParseData(PKTBEGIN::LAYER_DATALINK);
			if (UCast(16)(Packet::ETHERNET_HEADER::EthernetType::ARP)
				== ARPReplyHole.EthernetHeader.Type)
			{
				if (static_cast<USHORT>(Packet::ARP_ARCH::Opcode::REPLY) !=
					ARPReplyHole.ARPFrame.Operation)
				{
					continue;
				}
				if (Net::IPInfo{ ARPReplyHole.ARPFrame.SenderIP } == TargetSpoof)
				{
					SuccessReceived = true;
					break;
				}
			}

			if (duration<double>(system_clock::now() - Start).count() > TimeLimit)
			{
				SuccessReceived = false;
				break;
			}
		} while (Ret >= 0);

		return ARPReplyHole.EthernetHeader.Source;
	}

public:
	void ARPSpoof::Reply(void);
	void ARPSpoof::Relay(void);
	bool ARPSpoof::IsARPValid(void);
};

#endif /* _TANGU_SPOOF */
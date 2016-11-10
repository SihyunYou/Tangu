#pragma once

#include <IoStream>
#include <IoManip>

using namespace std;

#include "tangu_spoof.hpp"
#include "tangu_ping.hpp"
#include "tangu_blocker.hpp"

typedef pcap_if PCAP_INTERFACE;
typedef pcap_if* PPCAP_INTERFACE;
typedef pcap_t PCAP;
typedef pcap_t* PPCAP;

class JyPcap
{
private:
	PPCAP_INTERFACE FirstDevice;
	PPCAP_INTERFACE Device;
	INT DeviceNum;

public:
	PPCAP Interface;
	CHAR Error[PCAP_ERRBUF_SIZE];

public:
	JyPcap::JyPcap(bool(*IsMyDevice)(PPCAP_INTERFACE))
		: DeviceNum(0)
	{
		pcap_findalldevs(&FirstDevice, Error);

		Device = FirstDevice;
		while (Device)
		{
			if (IsMyDevice(Device))
			{
				break;
			}
			Device = Device->next;
		}

		Interface = pcap_open_live(Device->name, 65536, 1, 1000, Error);
	}
};

bool IsMyDevice(PPCAP_INTERFACE Device)
{
	return (strstr(Device->description, "Microsoft") != NULL) ? true : false;
}

int main(int argc, char *argv[])
{
	if (argc != 2)
	{
		cerr << "<Usage> : jping {IP to ping}\n";
		return EXIT_FAILURE;
	}
	
	using namespace Net;
	using namespace Packet;

	JyPcap MyPcap(&IsMyDevice);
	PacketGrouper MyPing(&MyPcap.Interface, IPInfo{ argv[1] });
	while (true)
	{
		MyPing.Ping(ICMP_ARCH::ICMPType::ICMP_ECHO);
	}

#if 0
	Net::IPInfo TargetIP{ string{argv[1]} };
	ARPSpoofer SnoopSpy(&Interface, TargetIP);

	if (SnoopSpy.IsARPValid())
	{
		cout << "\nTarget resources have been found out!\n";
		cout << "忙式式式式式式式式式式式式式式式式式式式式忖\n";
		cout << "弛  [  Target  MAC ] : " + SnoopSpy._ARPFrame._Rsrc.MDst.uc_bstr() + "  弛\n";
		cout <<  "弛  [  Gateway MAC ] : " + SnoopSpy._Gateway.first.uc_bstr() + "  弛\n";
		cout << "戌式式式式式式式式式式式式式式式式式式式式戎\n";
	}
	else
	{
		cout << L"Failed to search target or gateway resources. (TIMED OUT)\n";
		return EXIT_FAILURE;
	}

	cout << "Start ARP Reply...\n";
	cout << "Start Target (" + SnoopSpy._ARPFrame._Rsrc.MDst.uc_bstr() + ")'s Packet Relay...  ";
	
	thread Reply([&]()
	{
		/* Reply fake ARP to the victim per 30s. */
		while (Net::Utility::RecoveryPeriod(30000))
		{
			SnoopSpy.Reply();
		}
	});
	thread Relay([&]()
	{
		/* Monitoring packets that the victim sends to an attacker. (faked gateway) */
		/* Those are relayed to gateway with altered source MAC */
		SnoopSpy.Relay();
	});

	while (true) { ; }

	pcap_freealldevs(AllDevices);
	pcap_close(Interface);
			
	return EXIT_SUCCESS;
#endif

#if 0
	if (argc < 2)
	{
		cerr << "<Usage> : " << argv[0] << "blacklist.txt [blacklist2.txt ...]\n";
		return EXIT_FAILURE;
	}

	BlackList SnoopSpy{ argv[1] };
	WinDivertDev MyWinDivert;
	if (MyWinDivert.IsValid())
	{
		cerr << "Failed to open WinDivert device (" << GetLastError() << ")\n";
		return EXIT_FAILURE;
	}

	Common CmnParser{ nullptr };
	PacketAnalyzer* Analyzer{ &CmnParser };
	while (true)
	{
		if (!MyWinDivert.Recv())
		{
			cerr << "Warning : Failed to read packet (Errno : " << GetLastError() << ")\n";
			continue;
		}

		Analyzer->PktParser((const byte*)MyWinDivert.Packet, PktBegin::LAYER_NETWORK);
		if (SnoopSpy.PayloadMatch(CmnParser._HTTP))
		{
			if (!MyWinDivert.Send())
			{
				cerr << "Warning : Failed to reinject packet (Errno : " << GetLastError() << ")\n";
			}
		}
	}

#endif


}
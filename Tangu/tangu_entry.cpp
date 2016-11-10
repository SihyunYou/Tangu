#pragma once

#include <IOStream>

#include "tangu_interface.hpp"
#define TANGU_PING
#if defined(TANGU_SPOOF)
#include "tangu_spoof.hpp"
#elif defined(TANGU_PING)
#include "tangu_ping.hpp"
#elif defined(TANGU_BLOCKER)
#include "tangu_blocker.hpp"
#endif

int main(int argc, char *argv[])
{
	using std::cout;
	using std::cerr;
	using namespace Net;
	using namespace Packet;

	PcapDevice MyPcap(&IsMyDeviceWithDescription);

#if defined(TANGU_SPOOF)
	
	if (argc != 2)
	{
		cerr << "<Usage> : jyspoof {IP to spoof}\n";
		return EXIT_FAILURE;
	}

	Net::IPInfo TargetIP{ string{ argv[1] } };
	ARPSpoofer SnoopSpy(&MyPcap.Interface, TargetIP);

	if (SnoopSpy.IsARPValid())
	{
		cout << "\nTarget resources have been found out!\n";
		cout << "忙式式式式式式式式式式式式式式式式式式式式忖\n";
		cout << "弛  [  Target  MAC ] : " + SnoopSpy._ARPFrame._Rsrc.MDst.uc_bstr() + "  弛\n";
		cout << "弛  [  Gateway MAC ] : " + SnoopSpy._Gateway.first.uc_bstr() + "  弛\n";
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

#elif defined(TANGU_PING)
	
	if (argc != 2)
	{
		cerr << "<Usage> : jyping {IP to ping}\n";
		return EXIT_FAILURE;
	}

	PacketGrouper MyPing(&MyPcap.Interface, IPInfo{ argv[1] });

	cout << "Pinging to " << argv[1] << ":\n";
	while (Net::Utility::RecoveryPeriod(1000))
	{
		MyPing.Ping(ICMP_ARCH::ICMPType::ICMP_ECHO);
	}

#elif defined(TANGU_BLOCKER)
	
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

	return EXIT_SUCCESS;
}

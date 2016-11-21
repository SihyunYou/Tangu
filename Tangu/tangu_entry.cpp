#pragma once

#include <IOStream>

#include "tangu_interface.hpp"
#define TANGU_PING
#if defined(TANGU_SPOOF)
#include "tangu_spoof.hpp"
#elif defined(TANGU_PING)
#include "tangu_ping.hpp"
#elif defined(TANGU_BLOCKER)
#include "tangu_analyzer.hpp"
#include "tangu_blocker.hpp"
#elif defined(TANGU_ANALYZER_WINDIVERT)
#include "tangu_analyzer.hpp"
#elif defined(TANGU_ARP)
#include "tangu_analyzer.hpp"
#endif

INT main(INT argc, LPSTR argv[])
{
	using std::cout;
	using std::cerr;
	using namespace Net;
	using namespace Packet;

	PCAP_DEVICE PcapDev(&IsMyDeviceWithDescription);

#if defined(TANGU_SPOOF)
	if (argc != 2)
	{
		cerr << "<Usage> : jyspoof {IP to spoof}\n";
		return EXIT_FAILURE;
	}

	Net::IPInfo TargetIP{ string{ argv[1] } };
	ARPSpoof Spoofer(&PcapDev.Interface, TargetIP);

	if (Spoofer.IsARPValid())
	{
		cout << "\nTarget resources have been found out!\n";
		cout << "忙式式式式式式式式式式式式式式式式式式式式忖\n";
		cout << "弛  [  Target  MAC ] : " + Spoofer.ARPFrame._Rsrc.MDst() + "  弛\n";
		cout << "弛  [  Gateway MAC ] : " + Spoofer.Gateway.first() + "  弛\n";
		cout << "戌式式式式式式式式式式式式式式式式式式式式戎\n";
	}
	else
	{
		cout << L"Failed to search target or gateway resources. (TIMED OUT)\n";
		return EXIT_FAILURE;
	}

	cout << "Start ARP Reply...\n";
	cout << "Start Target (" + Spoofer.ARPFrame._Rsrc.MDst() + ")'s Packet Relay...  ";

	thread Reply([&]()
	{
		//
		// Reply fake ARP to the victim per 30s.
		//
		while (true)
		{
			
			Spoofer.Reply();
		}
	});
	thread Relay([&]()
	{
		//
		// Monitor packets that the victim sends to an attacker. (faked gateway) */
		// Those will be relayed to gateway with altered source MAC 
		//
		Spoofer.Relay();
	});

	while (true) { ; }

#elif defined(TANGU_PING)
	if (argc != 2)
	{
		cerr << "<Usage> : jyping {IP to ping}\n";
		return EXIT_FAILURE;
	}

	IPInfo Target{ argv[1] };
	PacketGrouper Pinger(&PcapDev.Interface, Target);
	TIME_POINT TimePoint;

	cout << "Pinging to " << Target() << ":\n";
	do
	{
		Re_echo: TimePoint.Start = system_clock::now();
		if (true != Pinger.Echo(2000))
		{
			cout << "Requested time out.\n";
			goto Re_echo;
		}

		TimePoint.End = system_clock::now();
		cout << "Reply of " << Target() << ": " << TimePoint() << "ms\n";

		Sleep(1000);
	}while (true);

	PacketGrouper::STATISTICS& Stats = Pinger.GetStats();
	UINT Ratio = (0 == Stats.Lost) ? 0 : (Stats.Lost * 100) / Stats.Sent;

	cout << "\nPing statistics to " << Target() << ":\n";
	cout << "\tPacket : Sent = " << Stats.Sent <<
		", Received = " << Stats.Received <<
		", Lost = " << Stats.Lost;
	cout << "(" << Ratio << "% Lost)\n";

#elif defined(TANGU_BLOCKER)
	if (2 > argc)
	{
		cerr << "<Usage> : " << argv[0] << "blacklist.txt [blacklist2.txt ...]\n";
		return EXIT_FAILURE;
	}

	BADURL_LIST BadUrlList{ argv[1] };
	PACKET_INFO PacketInfo;
	
	try
	{
		WINDIVERT_DEVICE WinDivertDev{ "outbound" };
		while (true)
		{
			auto Payload{ WinDivertDev.Receive() };
			string Contents{ PacketInfo.PktParseString(Payload, PKTBEGIN::LAYER_NETWORK) };
			cout << Contents << std::endl;
			
			if (BadUrlList.Match((LPSTR)PacketInfo.ApplicationPayload))
			{
				WinDivertDev.Send();
			}
		}
	}
	catch (Win32Exception& ExceptWin32)
	{
		cerr << ExceptWin32.what() << std::endl;
	}

#elif defined(TANGU_ANALYZER_WINDIVERT)
	PACKET_INFO PacketInfo;
	
	try
	{
		WINDIVERT_DEVICE WinDivertDev{ "outbound" };
		while (true)
		{
			auto Payload{ WinDivertDev.ReceiveAndSend() };
			string Contents{ PacketInfo.PktParseString(Payload) };		
			cout << Contents << std::endl;
		}
	}
	catch (Win32Exception& ExceptWin32)
	{
		cerr << ExceptWin32.what() << std::endl;
		return EXIT_FAILURE;
	}

#elif defined(TANGU_ARP)
	PIPNetTableInfo IpNetRow = Net::IPNetTableInfo::GetInstance();
	PMIB_IPNETTABLE Table = IpNetRow->GetTable();
	PMIB_IPNETROW Row;

	cout << "Internet Address\tPhysical Address\t Type\n";
	for (INT i = 0; i != Table->dwNumEntries; ++i)
	{
		Row = &(Table->table[i]);
		cout << IPInfo{ ntohl(Row->dwAddr) }() << "\t\t" << 
			MACInfo{ Row->bPhysAddr }() << "\t" << 
			IpNetRow->Type[Row->dwType - 1] << std::endl;
	}

#endif
	return EXIT_SUCCESS;
}

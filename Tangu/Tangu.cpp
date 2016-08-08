#pragma once

#include <IoStream>
#include <IoManip>

using namespace std;

#include "TanguSpoof"
#include "TanguPing"
#include "TanguBlocker"

int main(int argc, char *argv[])
{
#if 0
	if (argc != 2)
	{
		cerr << "<Usage> : arpspoof {IP To Spoof}\n";
		return EXIT_FAILURE;
	}

	using namespace Net;

	pcap_if_t*				AllDevices;
	pcap_if_t*				Device;
	UINT32						DeviceChosen{ 0 };
	CHAR						Error[PCAP_ERRBUF_SIZE];
	INT32						DeviceNum{ 0 };

	pcap_findalldevs(&AllDevices, Error);

	for (Device = AllDevices; Device; Device = Device->next)
	{
		cout << "[" << setfill('0') << setw(2) << ++DeviceNum << "] " << Device->name << " : " << Device->description << endl;
	}

	while (DeviceChosen < 1 || DeviceChosen > DeviceNum)
	{
		cout << "Manage Interface (1 ~ " << DeviceNum << ") : ";
		cin >> DeviceChosen;

		if (DeviceChosen < 1 || DeviceChosen > DeviceNum)
		{
			cerr << L"Invalid Device Number\n";
		}
	}

	Device = AllDevices;
	while (--DeviceChosen > 0)
	{
		Device = Device->next;
	}

	pcap_t*	Interface{ pcap_open_live(Device->name, 65536, 1, 1000, Error) };
	if (nullptr == &Interface)
	{
		cerr << L"Couldn't open device " << Device->name << " : " << Error << endl;
		return EXIT_FAILURE;
	}
	cout << "Searching network resources...  ";

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
}
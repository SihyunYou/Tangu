#include <IOStream>
#include <tangu\tangu_interface.hpp>
#include <tangu\tangu_ping.hpp>

#pragma comment(lib, "tangu.lib")

INT main(INT argc, LPSTR argv[])
{
	using std::cout;
	using std::cerr;
	using namespace Net;
	using namespace Packet;

	PCAP_DEVICE PcapDev(&IsMyDeviceWithDescription);

	if (argc != 2)
	{
		cerr << "<Usage> : tangu_ping {IP to ping}\n";
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
	} while (true);

	PacketGrouper::STATISTICS& Stats = Pinger.GetStats();
	UINT Ratio = (0 == Stats.Lost) ? 0 : (Stats.Lost * 100) / Stats.Sent;

	cout << "\nPing statistics to " << Target() << ":\n";
	cout << "\tPacket : Sent = " << Stats.Sent <<
		", Received = " << Stats.Received <<
		", Lost = " << Stats.Lost;
	cout << "(" << Ratio << "% Lost)\n";
}
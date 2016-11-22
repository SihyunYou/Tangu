#include <IOStream>
#include <tangu\tangu_interface.hpp>
#include <tangu\tangu_analyzer.hpp>

#pragma comment(lib, "tangu.lib")

INT main(INT argc, LPSTR argv[])
{
	using std::cout;
	using std::cerr;
	using namespace Net;
	using namespace Packet;

	PCAP_DEVICE PcapDev(&IsMyDeviceWithDescription);
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
}
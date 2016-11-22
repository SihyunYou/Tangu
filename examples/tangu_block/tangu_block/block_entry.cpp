#include <IOStream>
#include <tangu\tangu_blocker.hpp>
#include <tangu\tangu_analyzer.hpp>

#pragma comment(lib, "tangu.lib")

INT main(INT argc, LPSTR argv[])
{
	using std::cout;
	using std::cerr;
	using namespace Net;
	using namespace Packet;

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
}
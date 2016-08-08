#pragma once

#include "TanguBlocker"

BlackList::BlackList(const char* mal_site_txt) :
	MalformedList{ mal_site_txt, ios::in },
	LoggerMalsite{ "C:\\warning.log", ios::out }
{
	assert(LoggerMalsite.is_open());

	string Ban;
	size_t Pos;
	It = BlockedURL.before_begin();
	while (MalformedList.good())
	{
		std::getline(MalformedList, Ban);
	
		boost::algorithm::erase_all(Ban, "http://");
		boost::algorithm::erase_all(Ban, " "); // gilgil gave me some strange unicodes, too!
		printf("%s  \n", Ban.c_str());
		It = BlockedURL.insert_after(It, Ban);
	}
	MalformedList.close();

	time(&RawTime);
	localtime_s(&TimeInfo, &RawTime);
}
BlackList::~BlackList()
{
	LoggerMalsite.close();
}

void BlackList::LogAccessMalsite()
{
	strftime(TimeBuf, sizeof(TimeBuf), "%d-%m-%Y %H-%M-%S", &TimeInfo);
}

void BlackList::Add(string URL)
{
	It = BlockedURL.insert_after(It, URL);
}
bool BlackList::PayloadMatch(HTTPHeader HTTPPayload)
{
	HTTPParsedInfo.clear();

	std::istringstream Resp{ HTTPPayload };
	string Token;
	string::size_type Index;
	while (std::getline(Resp, Token))
	{
		Index = Token.find(':', 0);
		if (Index != string::npos)
		{
			HTTPParsedInfo.insert(make_pair(Token.substr(0, Index), Token.substr(Index + 1)));
		}
	}

	for (auto& Key : HTTPParsedInfo)
	{
		if (Key.first == "Host")
		{
			for (auto& Lock : BlockedURL)
			{
				if (Key.second.find(Lock) != string::npos)
				{
					LogAccessMalsite();
					LoggerMalsite << TimeBuf << ' ' << Lock << std::endl << std::flush;

					return false;
				}
			}
		}
	}

	return true;
}


WinDivertDev::WinDivertDev() :
	HDivertDev{ WinDivertOpen
	(
		"outbound && ip && tcp.DstPort == 80 && tcp.PayloadLength > 0",
		WINDIVERT_LAYER_NETWORK, 404, 0
	) }
{

}


bool WinDivertDev::IsValid()
{
	return HDivertDev == INVALID_HANDLE_VALUE;
}
BOOL WinDivertDev::Recv()
{
	return WinDivertRecv(HDivertDev, Packet, sizeof(Packet), &PAddr, &ReadLen);
}
BOOL WinDivertDev::Send()
{
	return WinDivertSend(HDivertDev, Packet, ReadLen, &PAddr, nullptr);
}
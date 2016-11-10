#pragma once
#ifndef _TANGU_BLOCK
#define _TANGU_BLOCK

#include "windivert.hpp"
#include <boost/algorithm/string.hpp>

class BlackList
{
private:
	ifstream		MalformedList;
	ofstream		LoggerMalsite;

	time_t		RawTime;
	struct tm		TimeInfo;
	char			TimeBuf[0x80];

	forward_list<string>::iterator It;
	forward_list<string> BlockedURL;
	unordered_map<string, string> HTTPParsedInfo;

public:
	BlackList::BlackList(const char*);
	BlackList::~BlackList();

private:
	void BlackList::LogAccessMalsite();

public:
	void BlackList::Add(string URL);
	bool BlackList::PayloadMatch(HTTPHeader HTTPPayload);
};

class WinDivertDev
{
private:
	WINDIVERT_ADDRESS	PAddr;
	UINT						ReadLen;
	HANDLE					HDivertDev;

public:
	BYTE						Packet[0xFFFF];
	UINT						PacketLen{ 0 };

public:
	WinDivertDev::WinDivertDev();

public:
	bool WinDivertDev::IsValid();
	BOOL WinDivertDev::Recv();
	BOOL WinDivertDev::Send();
};

#endif /* _TANGU_BLOCK */
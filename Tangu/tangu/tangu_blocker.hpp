#pragma once
#ifndef _TANGU_BLOCK
#define _TANGU_BLOCK

#include <net_manager\net_manager.hpp>
#include <packet_field\packet_field.hpp>
#include <boost/algorithm/string.hpp>
namespace Algorithm = boost::algorithm;

typedef class TANGU_API _BADURL_LIST
{
private:
	ifstream UrlStream;
#define LOGGER_PATH "C:\\warning.log"
	ofstream LogStream;

	time_t RawTime;
	struct tm TimeInfo;
	CHAR TimeBuf[0x80];

	forward_list<string> BlockedURL;
	forward_list<string>::iterator It;

public:
	explicit _BADURL_LIST::_BADURL_LIST(LPCSTR);
	_BADURL_LIST::~_BADURL_LIST(void);

private:
	void _BADURL_LIST::LogAccess(void);

public:
	void _BADURL_LIST::Add(string);
	bool _BADURL_LIST::Match(LPSTR);
}BADURL_LIST, *PBADURL_LIST;


#endif /* _TANGU_BLOCK */
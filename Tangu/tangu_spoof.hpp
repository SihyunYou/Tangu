#pragma once
#ifndef _TANGU_SPOOF
#define _TANGU_SPOOF

#include "tangu_analyzer.hpp"

class ARPSpoofer : public NetInfo
{
public:
	pair<Net::MACInfo, Net::IPInfo>	_Gateway;

public:
	ARPSpoofer::ARPSpoofer(pcap_t**, Net::IPInfo);

public:
	void ARPSpoofer::Reply(void);
	void ARPSpoofer::Relay(void);
};

#endif /* _TANGU_SPOOF */
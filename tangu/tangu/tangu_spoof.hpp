//
// tangu_spoof.hpp
// Copyright © jynis2937, all rights reserved,
// This program is under the GNU Lesser General Public License.
//

#pragma once
#ifndef _TANGU_SPOOF
#define _TANGU_SPOOF

#include <tangu\tangu_analyzer.hpp>

/*
* @brief    ARP spoofer
*           ARP spoofing, ARP cache poisoning, or ARP poison routing, is 
*           a technique by which an attacker sends (spoofed) Address 
*           Resolution Protocol (ARP) messages onto a local area network.
*/
class TANGU_API ARPSpoof : protected PCAPTOOL
{
public:
	Packet::ARP ARPFrame;
	pair<Net::MACInfo, Net::IPInfo> Gateway;
	bool SuccessReceived;
	INT Ret;

public:
	/*
	* @brief    Constructor
	*          Initializes Pcap interface.
	*          Initialize source address and destination address.
	* @param    Pcap interface
	* @param    Target IP
	*/
	ARPSpoof::ARPSpoof(PPCAP*, Net::IPInfo);

protected:
	/*
	* @brief    Generates the ARP request or reply packet.
	* @param    ARP operation code
	*/
	void ARPSpoof::GenerateARP(Packet::ARP_ARCH::Opcode);
	/*
	* @brief    Gets other host's MAC address in local area network. 
	* @param    Target IP
	* @param    Time limit
	* @return   Target MAC
	* @deprecated    Will be divided into another class.
	*/
	Net::MACInfo ARPSpoof::GetMACAddress(Net::IPInfo&, double);

public:
	/*
	* @brief    Generates the ARP reply packet for poisioning table.
	*           Fake your IP address to gateway IP address. 
	*/
	void ARPSpoof::Reply(void);
	void ARPSpoof::Relay(void);
	bool ARPSpoof::IsARPValid(void);
};

#endif /* _TANGU_SPOOF */
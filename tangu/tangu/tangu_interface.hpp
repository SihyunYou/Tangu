#pragma once
#ifndef _TANGU_INTERFACE
#define _TANGU_INTERFACE

#include <net_manager\net_manager.hpp>
#include <packet_field\packet_field.hpp>
#include <tangu\tangu_exception.hpp>

typedef pcap_if PCAP_INTERFACE;
typedef pcap_if* PPCAP_INTERFACE;
typedef pcap_t PCAP;
typedef pcap_t* PPCAP;
typedef pcap_addr_t PCAP_ADDRESS;
typedef pcap_addr_t* PPCAP_ADDRESS;
typedef bpf_u_int32 BPF_UINT;
typedef bpf_u_int32* PBPF_UINT;
typedef struct pcap_pkthdr PCAP_PKTHDR;
typedef struct pcap_pkthdr* PPCAP_PKTHDR;

typedef class TANGU_API PCAP_DEVICE
{
private:
	PPCAP_INTERFACE FirstDevice;
	PPCAP_INTERFACE Device;
	INT DeviceNum;
	INT Status;
	PCHAR DeviceChar;
	BPF_UINT Net;
	BPF_UINT Mask;

public:
	PPCAP Interface;
	CHAR Error[PCAP_ERRBUF_SIZE];

public:
	explicit PCAP_DEVICE::PCAP_DEVICE(std::function<bool(PPCAP_INTERFACE)>&);
	PCAP_DEVICE::PCAP_DEVICE(void);
	PCAP_DEVICE::~PCAP_DEVICE(void);

private:
	void PCAP_DEVICE::OpenLive(LPSTR);
} *PPCAP_DEVICE;

extern auto IsMyDeviceWithAddress = 
[](PPCAP_INTERFACE Device) -> bool
{
	PPCAP_ADDRESS PcapAddress = Device->addresses;
	ADDRESS_FAMILY AddressFamily = PcapAddress->addr->sa_family;
	if (AF_INET == AddressFamily || AF_INET6 == AddressFamily)
	{
		if (PcapAddress->addr && PcapAddress->netmask)
		{
			Net::PIPAdapterInfo AddressInfo = Net::IPAdapterInfo::GetInstance();
			if (Net::Utility::GetIPAddress(AddressInfo) ==
				Net::IPInfo(((struct sockaddr_in*)(PcapAddress->addr))->sin_addr.s_addr))
			{
				return true;
			}
		}
	}
	return false;
};
extern auto IsMyDeviceWithDescriptor =
[](PPCAP_INTERFACE Device) -> bool
{
	return string(Device->description) == "Microsoft" ? true : false;
};


#endif /* _TANGU_INTERFACE */
#pragma once
#include "tangu_build.hpp"
#include "net_manager.hpp"

typedef pcap_if PCAP_INTERFACE;
typedef pcap_if* PPCAP_INTERFACE;
typedef pcap_t PCAP;
typedef pcap_t* PPCAP;
typedef pcap_addr_t PCAP_ADDRESS;
typedef pcap_addr_t* PPCAP_ADDRESS;
typedef bpf_u_int32 BPF_UINT;
typedef bpf_u_int32* PBPF_UINT;

class PcapDevice
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
	PcapDevice::PcapDevice(bool(*IsMyDevice)(PPCAP_INTERFACE));
	PcapDevice::PcapDevice(void);
	PcapDevice::~PcapDevice(void);

private:
	void PcapDevice::OpenLive(CHAR* DeviceName);
};

//
// PcapDevice(bool(*)(PPCAP_INTERFACE)) Callback Function
//
bool IsMyDeviceWithAddress(PPCAP_INTERFACE Device);
bool IsMyDeviceWithDescription(PPCAP_INTERFACE Device);
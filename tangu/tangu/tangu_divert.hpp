#pragma once
#include <tangu\tangu_analyzer.hpp>
#pragma comment(lib, "WinDivert.lib")

typedef class TANGU_API WINDIVERT_DEVICE
{
private:
	HANDLE DivertDevice;
	WINDIVERT_ADDRESS Address;
	PACKET_INFO PacketInfo;

public:
	BYTE Payload[_MAX_ETHERNETLEN];

	UINT ReadPacketLength;
	UINT WrittenPacketLength;

public:
	explicit WINDIVERT_DEVICE::WINDIVERT_DEVICE(LPCSTR);
	explicit WINDIVERT_DEVICE::WINDIVERT_DEVICE(HANDLE);
	WINDIVERT_DEVICE::~WINDIVERT_DEVICE(void);

private:
	void WINDIVERT_DEVICE::ThrowExcpetions(DWORD);

public:
	//
	// Packet reinjection under WINDIVERT_DEVICE instance.  
	//
	void _declspec(noreturn) WINDIVERT_DEVICE::Receive(void);
	void _declspec(noreturn) WINDIVERT_DEVICE::Send(void);

	//
	// Independent packet handler.  
	//
	void _declspec(noreturn) WINDIVERT_DEVICE::Send(LPCBYTE, UINT);
	void WINDIVERT_DEVICE::Parse(PKTBEGIN LayerToParse)
	{
		PacketInfo = Payload;
		PacketInfo.ParseData(LayerToParse);
	}
	bool IsOutBound(void)
	{
		return TRUE == Address.Direction;
	}
} *PWINDIVERT_DEVICE;

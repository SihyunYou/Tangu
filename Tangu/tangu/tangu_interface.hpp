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
typedef struct pcap_pkthdr PCAP_PKTHDR;
typedef struct pcap_pkthdr* PPCAP_PKTHDR;

class PCAP_DEVICE
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
	PCAP_DEVICE::PCAP_DEVICE(bool(*IsMyDevice)(PPCAP_INTERFACE));
	PCAP_DEVICE::PCAP_DEVICE(void);
	PCAP_DEVICE::~PCAP_DEVICE(void);

private:
	void PCAP_DEVICE::OpenLive(PCHAR DeviceName);
};

//
// PCAP_DEVICE(bool(*)(PPCAP_INTERFACE)) callback function
//
bool IsMyDeviceWithAddress(PPCAP_INTERFACE Device);
bool IsMyDeviceWithDescription(PPCAP_INTERFACE Device);



typedef class WINDIVERT_DEVICE
{
private:
	HANDLE HDivertDev;
	WINDIVERT_ADDRESS PAddr;
	UINT ReadLen;

public:
	BYTE Payload[0xFFFF];
	UINT PacketLen;

public:
#define And " && "
#define Or " || "
#define Equal(x, y) x##" == "##y
	explicit WINDIVERT_DEVICE::WINDIVERT_DEVICE(LPCSTR);
	WINDIVERT_DEVICE::~WINDIVERT_DEVICE(void);

public:
	const LPBYTE WINDIVERT_DEVICE::Receive(void);
	const LPBYTE WINDIVERT_DEVICE::Send(void);
	const LPBYTE WINDIVERT_DEVICE::ReceiveAndSend(void);
} *PWINDIVERT_DEVICE;


#include <boost\config.hpp>

class Win32Exception : public std::exception
{
private:
	string ErrorMesage;
	DWORD ErrorCode;
	
public: 
	Win32Exception::Win32Exception(DWORD Errno);

public:
	static std::exception_ptr FromLastError(void) noexcept;
	static std::exception_ptr FromWinError(DWORD Errno) noexcept;

	static void _declspec(noreturn) Throw(DWORD LastError);
	static void _declspec(noreturn) ThrowFromLastError(void);
	
	DWORD GetErrorCode(void) const;
	virtual LPCSTR what(void) const;
};

class ErrorSuccessException : public Win32Exception
{
public:
	ErrorSuccessException::ErrorSuccessException(void) :
		Win32Exception(ERROR_SUCCESS)
	{
	}
};

class ErrorFileNotFoundException : public Win32Exception
{
public:
	ErrorFileNotFoundException::ErrorFileNotFoundException(void) :
		Win32Exception(ERROR_FILE_NOT_FOUND)
	{
	}
};

class ErrorAccessDeniedException : public Win32Exception
{
public:
	ErrorAccessDeniedException::ErrorAccessDeniedException(void) :
		Win32Exception(ERROR_ACCESS_DENIED)
	{
	}
};

class ErrorInvalidHandleException : public Win32Exception
{
public:
	ErrorInvalidHandleException::ErrorInvalidHandleException(void) :
		Win32Exception(ERROR_INVALID_HANDLE)
	{
	}
};

class ErrorReadFaultException : public Win32Exception
{
public:
	ErrorReadFaultException::ErrorReadFaultException(void) :
		Win32Exception(ERROR_READ_FAULT)
	{
	}
};

class ErrorWriteFaultException : public Win32Exception
{
public:
	ErrorWriteFaultException::ErrorWriteFaultException(void) :
		Win32Exception(ERROR_WRITE_FAULT)
	{
	}
};

class ErrorAlreadyExistsException : public Win32Exception
{
public:
	ErrorAlreadyExistsException::ErrorAlreadyExistsException(void) :
		Win32Exception(ERROR_ALREADY_EXISTS)
	{
	}
};

class ErrorPathNotFoundException : public Win32Exception
{
public:
	ErrorPathNotFoundException::ErrorPathNotFoundException(void) :
		Win32Exception(ERROR_PATH_NOT_FOUND)
	{
	}
};

class ErrorInvalidParameterException : public Win32Exception
{
public:
	ErrorInvalidParameterException::ErrorInvalidParameterException(void) :
		Win32Exception(ERROR_INVALID_PARAMETER)
	{
	}
};

class ErrorModuleNotFoundException : public Win32Exception
{
public:
	ErrorModuleNotFoundException::ErrorModuleNotFoundException(void) :
		Win32Exception(ERROR_MOD_NOT_FOUND)
	{
	}
};

class ErrorProcedureNotFoundException : public Win32Exception
{
public:
	ErrorProcedureNotFoundException::ErrorProcedureNotFoundException(void) :
		Win32Exception(ERROR_PROC_NOT_FOUND)
	{
	}
};

class ErrorInvalidImageHashException : public Win32Exception
{
public:
	ErrorInvalidImageHashException::ErrorInvalidImageHashException(void) :
		Win32Exception(ERROR_INVALID_IMAGE_HASH)
	{
	}
};

class ErrorDriverBlockedException : public Win32Exception
{
public:
	ErrorDriverBlockedException::ErrorDriverBlockedException(void) :
		Win32Exception(ERROR_DRIVER_BLOCKED)
	{
	}
};
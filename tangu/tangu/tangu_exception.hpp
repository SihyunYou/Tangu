//
// tangu_exception.hpp
// Copyright © jynis2937, all rights reserved,
// This program is under the GNU Lesser General Public License.
//

#pragma once
#include <tangu\tangu_build.hpp>

class Win32Exception : public std::exception
{
private:
	DWORD _ErrorCode;

public:
	Win32Exception::Win32Exception(DWORD Errno);
	virtual Win32Exception::~Win32Exception(void);

public:
	static std::exception_ptr Win32Exception::FromLastError(void) noexcept;
	static std::exception_ptr Win32Exception::FromWinError(DWORD) noexcept;

	static void _declspec(noreturn) Win32Exception::Throw(DWORD);
	static void _declspec(noreturn) Win32Exception::ThrowFromLastError(void);

	DWORD Win32Exception::get(void) const;
	virtual LPCSTR Win32Exception::what(void) const;
};

class ErrorSuccessException : public Win32Exception
{
public:
	ErrorSuccessException::ErrorSuccessException(void) :
		Win32Exception(ERROR_SUCCESS)
	{
	}
};

class ErrorInvalidFunctionException : public Win32Exception
{
public:
	ErrorInvalidFunctionException::ErrorInvalidFunctionException(void) :
		Win32Exception(ERROR_INVALID_FUNCTION)
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

class ErrorPathNotFoundException : public Win32Exception
{
public:
	ErrorPathNotFoundException::ErrorPathNotFoundException(void) :
		Win32Exception(ERROR_PATH_NOT_FOUND)
	{
	}
};

class ErrorTooManyOpenFilesException : public Win32Exception
{
public:
	ErrorTooManyOpenFilesException::ErrorTooManyOpenFilesException(void) :
		Win32Exception(ERROR_TOO_MANY_OPEN_FILES)
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

class ErrorInvalidAccessException : public Win32Exception
{
public:
	ErrorInvalidAccessException::ErrorInvalidAccessException(void) :
		Win32Exception(ERROR_INVALID_ACCESS)
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

class ErrorReadFaultException : public Win32Exception
{
public:
	ErrorReadFaultException::ErrorReadFaultException(void) :
		Win32Exception(ERROR_READ_FAULT)
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

class ErrorOpenFailedException : public Win32Exception
{
public:
	ErrorOpenFailedException::ErrorOpenFailedException(void) :
		Win32Exception(ERROR_OPEN_FAILED)
	{
	}
};

class ErrorProcNotFoundException : public Win32Exception
{
public:
	ErrorProcNotFoundException::ErrorProcNotFoundException(void) :
		Win32Exception(ERROR_PROC_NOT_FOUND)
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

class ErrorDataNotAcceptedException : public Win32Exception
{
public:
	ErrorDataNotAcceptedException::ErrorDataNotAcceptedException(void) :
		Win32Exception(ERROR_DATA_NOT_ACCEPTED)
	{
	}
};

class ErrorRetryException : public Win32Exception
{
public:
	ErrorRetryException::ErrorRetryException(void) :
		Win32Exception(ERROR_RETRY)
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
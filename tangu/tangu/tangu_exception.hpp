//
// tangu_exception.hpp
// Copyright © jynis2937, all rights reserved,
// This program is under the GNU Lesser General Public License.
//

#pragma once
#include <tangu\tangu_build.hpp>

/*
* @brief    A nice wrapper for throwing exceptions around Win32 errors
*/
class Win32Exception : public std::exception
{
private:
	DWORD _ErrorCode;

public:
	/*
	* @brief    Constructor
	* @param	    winerror 
	*/
	Win32Exception::Win32Exception(DWORD);
	/*
	* @brief    Destructor
	*/
	virtual Win32Exception::~Win32Exception(void);

public:
	/*
	* @param	    winerror
	* @return   The supplied error instance as an exception_ptr.
	*/
	exception_ptr static Win32Exception::FromWinError(DWORD) noexcept;
	/*
	* @return   The last error instance as an exception_ptr.
	* @see      ::GetLastError()
	*/
	exception_ptr static Win32Exception::FromLastError(void) noexcept;
	
	/*
	* @brief    Throws a specified error directly.
	* @param    winerror to throw. (usually a captured error code)
	*/
	void static _declspec(noreturn) Win32Exception::Throw(DWORD);
	/*
	* @brief    Throws from last error.
	* @see      Win32Exception::FromLastError()
	*/
	void static _declspec(noreturn) Win32Exception::ThrowFromLastError(void);

	/*
	* @brief    Gets the error code.
	* @return   The winerror code which initialized the instance.
	*/
	DWORD Win32Exception::get(void) const;
	/*
	* @brief    Gets the error string.
	* @return   The string description for looking up error.
	*/
	virtual LPCSTR Win32Exception::what(void) const;
};

/*
* @brief    Exception for signaling ERROR_SUCCESS.
*/ 
class ErrorSuccessException : public Win32Exception
{
public:
	ErrorSuccessException::ErrorSuccessException(void) :
		Win32Exception(ERROR_SUCCESS)
	{
	}
};

/*
* @brief    Exception for signaling ERROR_INVALID_FUNCTION.
*/
class ErrorInvalidFunctionException : public Win32Exception
{
public:
	ErrorInvalidFunctionException::ErrorInvalidFunctionException(void) :
		Win32Exception(ERROR_INVALID_FUNCTION)
	{
	}
};

/*
* @brief    Exception for signaling ERROR_FILE_NOT_FOUND.
*/
class ErrorFileNotFoundException : public Win32Exception
{
public:
	ErrorFileNotFoundException::ErrorFileNotFoundException(void) :
		Win32Exception(ERROR_FILE_NOT_FOUND)
	{
	}
};

/*
* @brief    Exception for signaling ERROR_PATH_NOT_FOUND.
*/
class ErrorPathNotFoundException : public Win32Exception
{
public:
	ErrorPathNotFoundException::ErrorPathNotFoundException(void) :
		Win32Exception(ERROR_PATH_NOT_FOUND)
	{
	}
};

/*
* @brief    Exception for signaling ERROR_TOO_MANY_OPEN_FILES.
*/
class ErrorTooManyOpenFilesException : public Win32Exception
{
public:
	ErrorTooManyOpenFilesException::ErrorTooManyOpenFilesException(void) :
		Win32Exception(ERROR_TOO_MANY_OPEN_FILES)
	{
	}
};

/*
* @brief    Exception for signaling ERROR_ACCESS_DENIED.
*/
class ErrorAccessDeniedException : public Win32Exception
{
public:
	ErrorAccessDeniedException::ErrorAccessDeniedException(void) :
		Win32Exception(ERROR_ACCESS_DENIED)
	{
	}
};

/*
* @brief    Exception for signaling ERROR_INVALID_HANDLE.
*/
class ErrorInvalidHandleException : public Win32Exception
{
public:
	ErrorInvalidHandleException::ErrorInvalidHandleException(void) :
		Win32Exception(ERROR_INVALID_HANDLE)
	{
	}
};

/*
* @brief    Exception for signaling ERROR_INVALID_ACCESS.
*/
class ErrorInvalidAccessException : public Win32Exception
{
public:
	ErrorInvalidAccessException::ErrorInvalidAccessException(void) :
		Win32Exception(ERROR_INVALID_ACCESS)
	{
	}
};

/*
* @brief    Exception for signaling ERROR_WRITE_FAULT.
*/
class ErrorWriteFaultException : public Win32Exception
{
public:
	ErrorWriteFaultException::ErrorWriteFaultException(void) :
		Win32Exception(ERROR_WRITE_FAULT)
	{
	}
};

/*
* @brief    Exception for signaling ERROR_READ_FAULT.
*/
class ErrorReadFaultException : public Win32Exception
{
public:
	ErrorReadFaultException::ErrorReadFaultException(void) :
		Win32Exception(ERROR_READ_FAULT)
	{
	}
};

/*
* @brief    Exception for signaling ERROR_INVALID_PARAMETER.
*/
class ErrorInvalidParameterException : public Win32Exception
{
public:
	ErrorInvalidParameterException::ErrorInvalidParameterException(void) :
		Win32Exception(ERROR_INVALID_PARAMETER)
	{
	}
};

/*
* @brief    Exception for signaling ERROR_OPEN_FAILED.
*/
class ErrorOpenFailedException : public Win32Exception
{
public:
	ErrorOpenFailedException::ErrorOpenFailedException(void) :
		Win32Exception(ERROR_OPEN_FAILED)
	{
	}
};

/*
* @brief    Exception for signaling ERROR_PROC_NOT_FOUND.
*/
class ErrorProcNotFoundException : public Win32Exception
{
public:
	ErrorProcNotFoundException::ErrorProcNotFoundException(void) :
		Win32Exception(ERROR_PROC_NOT_FOUND)
	{
	}
};

/*
* @brief    Exception for signaling ERROR_ALREADY_EXISTS.
*/
class ErrorAlreadyExistsException : public Win32Exception
{
public:
	ErrorAlreadyExistsException::ErrorAlreadyExistsException(void) :
		Win32Exception(ERROR_ALREADY_EXISTS)
	{
	}
};

/*
* @brief    Exception for signaling ERROR_MOD_NOT_FOUND.
*/
class ErrorModuleNotFoundException : public Win32Exception
{
public:
	ErrorModuleNotFoundException::ErrorModuleNotFoundException(void) :
		Win32Exception(ERROR_MOD_NOT_FOUND)
	{
	}
};

/*
* @brief    Exception for signaling ERROR_INVALID_IMAGE_HASH.
*/
class ErrorInvalidImageHashException : public Win32Exception
{
public:
	ErrorInvalidImageHashException::ErrorInvalidImageHashException(void) :
		Win32Exception(ERROR_INVALID_IMAGE_HASH)
	{
	}
};

/*
* @brief    Exception for signaling ERROR_DATA_NOT_ACCEPTED.
*/
class ErrorDataNotAcceptedException : public Win32Exception
{
public:
	ErrorDataNotAcceptedException::ErrorDataNotAcceptedException(void) :
		Win32Exception(ERROR_DATA_NOT_ACCEPTED)
	{
	}
};

/*
* @brief    Exception for signaling ERROR_RETRY.
*/
class ErrorRetryException : public Win32Exception
{
public:
	ErrorRetryException::ErrorRetryException(void) :
		Win32Exception(ERROR_RETRY)
	{
	}
};

/*
* @brief    Exception for signaling ERROR_DRIVER_BLOCKED.
*/
class ErrorDriverBlockedException : public Win32Exception
{
public:
	ErrorDriverBlockedException::ErrorDriverBlockedException(void) :
		Win32Exception(ERROR_DRIVER_BLOCKED)
	{
	}
};
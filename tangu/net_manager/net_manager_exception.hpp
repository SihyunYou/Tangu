//
// net_manager_exception.hpp
// Copyright © jynis2937, all rights reserved,
// This program is under the GNU Lesser General Public License.
//

#pragma once
#include <tangu\tangu_build.hpp>

NAMESPACE_BEGIN(Net)

enum class TANGU_API NET_ERROR
{
	ERROR_PASS,
	ERROR_INTEGER_OVERFLOW,
	ERROR_OUT_OF_INDEX,
	ERROR_INVALID_SUBNET_MASK,
	ERROR_ACCESS_VIOLATION,
};

/*
* @brief    A exception class for throwing exceptions around logical management area.
*/
class TANGU_API NetException : public std::exception
{
private:
	NET_ERROR _ErrorCode;

public:
	/*
	* @brief    Constructor
	* @param	    neterror, scoped enumerated.
	*/
	NetException::NetException(NET_ERROR);
	/*
	* @brief    Destructor
	*/
	virtual NetException::~NetException(void);

public:
	/*
	* @param	    neterror, scoped enumerated.
	* @return   The supplied error instance as an exception_ptr.
	*/
	exception_ptr static NetException::FromNetError(NET_ERROR) noexcept;
	/*
	* @brief    Throws a specified error directly.
	* @param    neterror to throw
	*/
	void static _declspec(noreturn) NetException::Throw(NET_ERROR);

public:
	/*
	* @brief    Gets the error code.
	* @return   The neterror code which initialized the instance.
	*/
	DWORD NetException::get(void) const;
	/*
	* @brief    Gets the error string.
	* @return   The string description for looking up error.
	*/
	virtual LPCSTR NetException::what(void) const;
};


/*
* @brief    Exception for signaling NET_ERROR::ERROR_PASS.
*/
class ErrorPassException : public NetException
{
public:
	ErrorPassException::ErrorPassException(void) :
		NetException(NET_ERROR::ERROR_PASS)
	{
	}
};

/*
* @brief    Exception for signaling NET_ERROR::ERROR_INTEGER_OVERFLOW.
*/
class ErrorIntegerOverflowException : public NetException
{
public:
	ErrorIntegerOverflowException::ErrorIntegerOverflowException(void) :
		NetException(NET_ERROR::ERROR_INTEGER_OVERFLOW)
	{
	}
};

/*
* @brief    Exception for signaling NET_ERROR::ERROR_OUT_OF_INDEX.
*/
class ErrorOutOfIndexException : public NetException
{
public:
	ErrorOutOfIndexException::ErrorOutOfIndexException(void) :
		NetException(NET_ERROR::ERROR_OUT_OF_INDEX)
	{
	}
};

/*
* @brief    Exception for signaling NET_ERROR::ERROR_INVALID_SUBNET_MASK.
*/
class ErrorInvalidSubnetMaskException : public NetException
{
public:
	ErrorInvalidSubnetMaskException::ErrorInvalidSubnetMaskException(void) :
		NetException(NET_ERROR::ERROR_INVALID_SUBNET_MASK)
	{
	}
};

/*
* @brief    Exception for signaling NET_ERROR::ERROR_ACCESS_VIOLATION.
*/
class ErrorAccessViolationException : public NetException
{
public:
	ErrorAccessViolationException::ErrorAccessViolationException(void) :
		NetException(NET_ERROR::ERROR_ACCESS_VIOLATION)
	{
	}
};

NAMESPACE_END

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

class TANGU_API NetException : public std::exception
{
private:
	NET_ERROR _ErrorCode;

public:
	NetException::NetException(NET_ERROR);
	virtual NetException::~NetException(void);

public:
	exception_ptr static NetException::FromNetError(NET_ERROR) noexcept;
	void static _declspec(noreturn) NetException::Throw(NET_ERROR);

public:
	DWORD NetException::get(void) const;
	virtual LPCSTR NetException::what(void) const;
};


class ErrorPassException : public NetException
{
public:
	ErrorPassException::ErrorPassException(void) :
		NetException(NET_ERROR::ERROR_PASS)
	{
	}
};

class ErrorIntegerOverflowException : public NetException
{
public:
	ErrorIntegerOverflowException::ErrorIntegerOverflowException(void) :
		NetException(NET_ERROR::ERROR_INTEGER_OVERFLOW)
	{
	}
};

class ErrorOutOfIndexException : public NetException
{
public:
	ErrorOutOfIndexException::ErrorOutOfIndexException(void) :
		NetException(NET_ERROR::ERROR_OUT_OF_INDEX)
	{
	}
};

class ErrorInvalidSubnetMaskException : public NetException
{
public:
	ErrorInvalidSubnetMaskException::ErrorInvalidSubnetMaskException(void) :
		NetException(NET_ERROR::ERROR_INVALID_SUBNET_MASK)
	{
	}
};

class ErrorAccessViolationException : public NetException
{
public:
	ErrorAccessViolationException::ErrorAccessViolationException(void) :
		NetException(NET_ERROR::ERROR_ACCESS_VIOLATION)
	{
	}
};

NAMESPACE_END

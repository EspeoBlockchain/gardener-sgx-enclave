#pragma once

#include <exception>
#include "sgx_urts.h"

struct SgxException : public std::exception {
private:
	sgx_status_t errorCode;
	char *buf;

public:
	SgxException(sgx_status_t errorCode);
	virtual ~SgxException();
	virtual const char * what() const throw ();
};
#pragma once

#include <exception>
#include "sgx_urts.h"

struct SgxException : public std::exception {
private:
	sgx_status_t errorCode;

public:
	SgxException(sgx_status_t errorCode);
	virtual const char * what() const throw ();
};
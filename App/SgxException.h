#pragma once

#include <exception>
#include <sstream>
#include "sgx_urts.h"

struct SgxException : public std::exception {
private:
	sgx_status_t errorCode;
	std::string buf;

public:
	SgxException(sgx_status_t errorCode);
	virtual const char * what() throw ();
};
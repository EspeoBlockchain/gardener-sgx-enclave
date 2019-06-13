#include "stdafx.h"
#include "SgxException.h"

#define BUFSIZE 256

SgxException::SgxException(sgx_status_t errorCode) {
	this->errorCode = errorCode;
}

const char * SgxException::what() throw () {
	std::stringstream stream;
	stream << "SGX Exception, error code was " << std::hex << errorCode << std::endl;
	buf = std::string(stream.str());

	return buf.c_str();
}
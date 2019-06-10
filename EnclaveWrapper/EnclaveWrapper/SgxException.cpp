#include "stdafx.h"
#include "SgxException.h"

#define BUFSIZE 256

SgxException::SgxException(sgx_status_t errorCode) {
	this->errorCode = errorCode;
}

const char * SgxException::what() const throw () {
	char *buf = (char*)malloc(BUFSIZE);
	sprintf_s(buf, BUFSIZE, "SGX Exception, error code was %x\n", errorCode);

	return buf;
}
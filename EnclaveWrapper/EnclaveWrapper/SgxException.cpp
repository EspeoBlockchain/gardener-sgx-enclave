#include "stdafx.h"
#include "SgxException.h"

#define BUFSIZE 256

SgxException::SgxException(sgx_status_t errorCode) {
	this->errorCode = errorCode;
	buf = (char*)malloc(BUFSIZE);
}

SgxException::~SgxException() {
	free(buf);
}

const char * SgxException::what() const throw () {
	sprintf_s(buf, BUFSIZE, "SGX Exception, error code was %x\n", errorCode);

	return buf;
}
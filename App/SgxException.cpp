#include <stdio.h>
#include "SgxException.h"

#define BUFSIZE 256

SgxException::SgxException(sgx_status_t errorCode) {
	this->errorCode = errorCode;
}

SgxException::SgxException(sgx_status_t errorCode, std::string message) {
	this->errorCode = errorCode;
	this->message = message;
}

const char * SgxException::what() throw () {
	std::stringstream stream;
	stream << "SGX Exception, error code was " << std::hex << errorCode << std::endl;
	if (!message.empty()) {
	    stream << "Additional info: " << message << std::endl;
	}

	buf.assign(stream.str());

	return buf.c_str();
}

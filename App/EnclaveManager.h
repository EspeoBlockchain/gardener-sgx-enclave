#pragma once

#include "sgx_urts.h"

#define ENCLAVE_FILENAME "Enclave.signed.so"

struct EnclaveManager {
private:
	sgx_enclave_id_t eid;

public:
	EnclaveManager();
	virtual ~EnclaveManager();
	unsigned long generateRandom();
};

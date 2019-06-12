#pragma once

#include "sgx_urts.h"

#define ENCLAVE_FILE _T("Enclave.signed.dll")

struct EnclaveManager {
private:
	sgx_enclave_id_t eid;

public:
	EnclaveManager();
	virtual ~EnclaveManager();
	unsigned int generateRandom(unsigned long *buf);
};
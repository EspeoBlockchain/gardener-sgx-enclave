#pragma once

#include "sgx_urts.h"

#include "../Attestation/protocol.h"

#define ENCLAVE_FILENAME "libs/Enclave.signed.so"

struct EnclaveManager {
private:
	sgx_enclave_id_t eid;

public:
	EnclaveManager();
	virtual ~EnclaveManager();
	unsigned long generateRandom();
	unsigned long generateAttestedRandom();
	attestation_status_t remoteAttestation();
	sgx_enclave_id_t getEnclaveId();
};

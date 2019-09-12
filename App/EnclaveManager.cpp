#include <stdio.h>
#include "EnclaveManager.h"
#include "SgxException.h"
#include "Enclave_u.h"
#include "ErrorCode.h"

EnclaveManager::EnclaveManager() {
	sgx_enclave_id_t eid;
	sgx_status_t ret = SGX_SUCCESS;
	sgx_launch_token_t token = { 0 };
	int updated = 0;

	ret = sgx_create_enclave(ENCLAVE_FILENAME, SGX_DEBUG_FLAG,
		&token, &updated,
		&eid, NULL);

	if (ret != SGX_SUCCESS) throw SgxException(ret);
	this->eid = eid;
}

EnclaveManager::~EnclaveManager() {
	sgx_status_t ret = SGX_SUCCESS;
	ret = sgx_destroy_enclave(eid);

	if (ret != SGX_SUCCESS) throw SgxException(ret);
}

unsigned long EnclaveManager::generateRandom() {
	unsigned int ret = FC_OK;
	unsigned long result;
	e_generate_random_long(eid, &ret, &result);
	if (ret != FC_OK) throw SgxException(SGX_ERROR_UNEXPECTED);

	return result;
}

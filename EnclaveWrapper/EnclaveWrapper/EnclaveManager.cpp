#include "stdafx.h"
#include "EnclaveManager.h"
#include "SgxException.h"
#include "Enclave_u.h"
#include "ErrorCode.h"

EnclaveManager::EnclaveManager() {
	sgx_enclave_id_t eid;
	sgx_status_t ret = SGX_SUCCESS;
	sgx_launch_token_t token = { 0 };
	int updated = 0;

	ret = sgx_create_enclave(ENCLAVE_FILE, SGX_DEBUG_FLAG,
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

unsigned int EnclaveManager::generateRandom(unsigned long *buf) {
	unsigned int ret = FC_OK;
	e_generate_random_long(eid, &ret, buf);
	if (ret != FC_OK) throw SgxException(SGX_ERROR_UNEXPECTED);

	return ret;
}
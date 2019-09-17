#ifndef __ATTESTATOR__H
#define __ATTESTATOR__H

#include <sgx_report.h>
#include <sgx_uae_service.h>
#include <sgx_ukey_exchange.h>
#include <sgx_utils.h>

#include "../Attestation/crypto.h"
#include "../Attestation/protocol.h"

typedef struct config_struct {
	char mode;
	uint32_t flags;
	sgx_spid_t spid;
	sgx_ec256_public_t pubkey;
	sgx_quote_nonce_t nonce;
	char *server;
	char *port;
} config_t;

attestation_status_t do_attestation (sgx_enclave_id_t eid, config_t *config);

void loadConfig(config_t *config);

sgx_status_t sgx_create_enclave_search (const char *filename, const int edebug,
	sgx_launch_token_t *token, int *updated, sgx_enclave_id_t *eid,
	sgx_misc_attribute_t *attr);

char* attestationStatusToString(attestation_status_t status);

#endif

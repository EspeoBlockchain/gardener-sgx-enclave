#include "EnclaveManager.h"
#include "SgxException.h"
#include "Enclave_u.h"
#include "ErrorCode.h"
#include "../Attestation/base64.h"
#include "../Attestation/iasrequest.h"
#include "../Attestation/protocol.h"
#include "../Attestation/msgio.h"
#include "../Attestation/enclave_verify.h"
#include "../Attestation/crypto.h"
#include "../Attestation/hexutil.h"
#include "../Attestation/json.h"

#include <sgx_report.h>
#include <sgx_uae_service.h>
#include <sgx_utils.h>
#include <time.h>
#include <string>
#include <cstdint>
#include <vector>
#include <iostream>
#include <stdio.h>

using std::vector;
using std::string;
using std::to_string;
using std::invalid_argument;

using namespace json;

typedef struct config_struct {
	sgx_spid_t spid;
	unsigned char pri_subscription_key[IAS_SUBSCRIPTION_KEY_SIZE+1];
	unsigned char sec_subscription_key[IAS_SUBSCRIPTION_KEY_SIZE+1];
	uint16_t quote_type;
	EVP_PKEY *service_private_key;
	char *proxy_server;
	char *ca_bundle;
	char *user_agent;
	unsigned int proxy_port;
	unsigned char kdk[16];
	X509_STORE *store;
	X509 *signing_ca;
	unsigned int apiver;
	int strict_trust;
	sgx_measurement_t req_mrsigner;
	sgx_prod_id_t req_isv_product_id;
	sgx_isv_svn_t min_isvsvn;
	int allow_debug_enclave;
} config_t;

typedef struct ra_session_struct {
	unsigned char g_a[64];
	unsigned char g_b[64];
	unsigned char kdk[16];
	unsigned char smk[16];
	unsigned char sk[16];
	unsigned char mk[16];
	unsigned char vk[16];
} ra_session_t;

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

void get_attestation(sgx_enclave_id_t eid, vector<uint8_t> *out) {
    sgx_target_info_t qe_info;
    sgx_epid_group_id_t p_gid;
    sgx_report_t report;
    sgx_spid_t spid;
    unsigned int ret;
    sgx_status_t ecall_ret;

    sgx_init_quote(&qe_info, &p_gid);

    memset(qe_info.reserved1, 0, sizeof qe_info.reserved1);
    memset(qe_info.reserved2, 0, sizeof qe_info.reserved2);
    ecall_ret = e_create_report(eid, &ret, &qe_info, &report);
    unsigned long result;

    if (ecall_ret != SGX_SUCCESS || ret) {
        std::cout << "e_create_report failed " << std::hex << ecall_ret << std::endl;
        throw SgxException(ecall_ret);
    }

    uint8_t spid_gardener[16] = {
      0x91, 0x1D, 0xBF, 0x50,
      0xF2, 0xEB, 0x6D, 0xBE,
      0x27, 0x78, 0x4F, 0x60,
      0xFF, 0xFB, 0xA8, 0x56,
    };

    memcpy(spid.id, spid_gardener, sizeof spid_gardener);

    uint32_t quote_size;
    sgx_calc_quote_size(nullptr, 0, &quote_size);
    auto *quote = reinterpret_cast<sgx_quote_t *>(malloc(quote_size));

    ecall_ret = sgx_get_quote(&report,
                            SGX_LINKABLE_SIGNATURE,
                            &spid, nullptr, nullptr,
                            0, nullptr, quote, quote_size);
    if (ecall_ret != SGX_SUCCESS) {
    std::cout << "sgx_get_quote failed " << std::hex << ecall_ret << std::endl;
        throw SgxException(ecall_ret);
    }

    out->insert(out->begin(), reinterpret_cast<uint8_t *>(quote),
              reinterpret_cast<uint8_t *>(quote) + quote_size);
    free(quote);
}

int get_attestation_report(IAS_Connection *ias, int version,
	const char *b64quote, sgx_ps_sec_prop_desc_t secprop, ra_msg4_t *msg4,
	int strict_trust)
{
	IAS_Request *req = NULL;
	map<string,string> payload;
	vector<string> messages;
	ias_error_t status;
	string content;

	try {
		req= new IAS_Request(ias, (uint16_t) version);
	}
	catch (...) {
		printf("Exception while creating IAS request object\n");
		if ( req != NULL ) delete req;
		return 0;
	}

	payload.insert(make_pair("isvEnclaveQuote", b64quote));

	status= req->report(payload, content, messages);
	if ( status == IAS_OK ) {
		JSON reportObj = JSON::Load(content);

        /*
         * If the report returned a version number (API v3 and above), make
         * sure it matches the API version we used to fetch the report.sourc
         *
         * For API v3 and up, this field MUST be in the report.
         */

        if (reportObj.hasKey("version") ) {
            unsigned int rversion= (unsigned int) reportObj["version"].ToInt();
            if ( version != rversion ) {
                printf("Report version %u does not match API version %u\n",
                    rversion , version);
                delete req;
                return 0;
            }
        } else if ( version >= 3 ) {
            printf("attestation report version required for API version >= 3\n");
            delete req;
            return 0;
        }

        /*
         * This sample's attestion policy is based on isvEnclaveQuoteStatus:
         *
         *   1) if "OK" then return "Trusted"
         *
         *   2) if "CONFIGURATION_NEEDED" then return
         *       "NotTrusted_ItsComplicated" when in --strict-trust-mode
         *        and "Trusted_ItsComplicated" otherwise
         *
         *   3) return "NotTrusted" for all other responses
         *
         *
         * ItsComplicated means the client is not trusted, but can
         * conceivable take action that will allow it to be trusted
         * (such as a BIOS update).
         */

        /*
         * Simply check to see if status is OK, else enclave considered
         * not trusted
         */

        memset(msg4, 0, sizeof(ra_msg4_t));

        if ( !(reportObj["isvEnclaveQuoteStatus"].ToString().compare("OK"))) {
            msg4->status = Trusted;
        } else if ( !(reportObj["isvEnclaveQuoteStatus"].ToString().compare("CONFIGURATION_NEEDED"))) {
            if ( strict_trust ) {
                msg4->status = NotTrusted_ItsComplicated;
                printf("Enclave NOT TRUSTED and COMPLICATED - Reason: %s\n",
                    reportObj["isvEnclaveQuoteStatus"].ToString().c_str());
            } else {
                printf("Enclave TRUSTED and COMPLICATED - Reason: %s\n",
                    reportObj["isvEnclaveQuoteStatus"].ToString().c_str());
                msg4->status = Trusted_ItsComplicated;
            }
        } else if ( !(reportObj["isvEnclaveQuoteStatus"].ToString().compare("GROUP_OUT_OF_DATE"))) {
            msg4->status = NotTrusted_ItsComplicated;
            printf("Enclave NOT TRUSTED and COMPLICATED - Reason: %s\n",
                reportObj["isvEnclaveQuoteStatus"].ToString().c_str());
        } else {
            msg4->status = NotTrusted;
            printf("Enclave NOT TRUSTED - Reason: %s\n",
                reportObj["isvEnclaveQuoteStatus"].ToString().c_str());
        }


        /* Check to see if a platformInfoBlob was sent back as part of the
         * response */

        if (!reportObj["platformInfoBlob"].IsNull()) {

            /* The platformInfoBlob has two parts, a TVL Header (4 bytes),
             * and TLV Payload (variable) */

            string pibBuff = reportObj["platformInfoBlob"].ToString();

            /* remove the TLV Header (8 base16 chars, ie. 4 bytes) from
             * the PIB Buff. */

            pibBuff.erase(pibBuff.begin(), pibBuff.begin() + (4*2));

            int ret = from_hexstring ((unsigned char *)&msg4->platformInfoBlob,
                pibBuff.c_str(), pibBuff.length()/2);
        }

            delete req;
            return 1;
	}

	printf("attestation query returned %lu: \n", status);

	switch(status) {
		case IAS_QUERY_FAILED:
			printf("Could not query IAS\n");
			break;
		case IAS_BADREQUEST:
			printf("Invalid payload\n");
			break;
		case IAS_UNAUTHORIZED:
			printf("Failed to authenticate or authorize request\n");
			break;
		case IAS_SERVER_ERR:
			printf("An internal error occurred on the IAS server\n");
			break;
		case IAS_UNAVAILABLE:
			printf("Service is currently not able to process the request. Try again later.\n");
			break;
		case IAS_INTERNAL_ERROR:
			printf("An internal error occurred while processing the IAS response\n");
			break;
		case IAS_BAD_CERTIFICATE:
			printf("The signing certificate could not be validated\n");
			break;
		case IAS_BAD_SIGNATURE:
			printf("The report signature could not be validated\n");
			break;
		default:
			if ( status >= 100 && status < 600 ) {
				printf("Unexpected HTTP response code\n");
			} else {
				printf("An unknown error occurred.\n");
			}
	}

	delete req;

	return 0;
}

unsigned int EnclaveManager::initRemoteAttestation() {
    std::vector<uint8_t> attestation;
    get_attestation(this->eid, &attestation);

    sgx_quote_t *q = (sgx_quote_t *) attestation.data();
    char *b64quote;
    size_t quoteSize = attestation.size();
//    b64quote = base64_decode(attestation.data(), attestation.size());
    b64quote = base64_decode(reinterpret_cast<const char*>(attestation.data()), &quoteSize);
    printf("quote size is %lu\n", attestation.size());
    printf("quote is %s\n", string(b64quote));

    ra_session_t *session;
	config_t *config;
    MsgIO *msgio = new MsgIO();
    ra_msg4_t *msg4;
    IAS_Connection *ias = new IAS_Connection(
    			IAS_SERVER_PRODUCTION,
    			0,
    			"c4e96b986c714d00b6b8e656764a5b79",
    			"3909408129a846fba63077f965623232"
    );

    sgx_ps_sec_prop_desc_t ps_sec_prop_desc;
    sgx_get_ps_sec_prop(&ps_sec_prop_desc);

    if (get_attestation_report(ias, IAS_API_DEF_VERSION, b64quote, ps_sec_prop_desc, msg4, 0) ) {

        unsigned char vfy_rdata[64];
        unsigned char msg_rdata[144]; /* for Ga || Gb || VK */

        sgx_report_body_t *r= (sgx_report_body_t *) &q->report_body;

        memset(vfy_rdata, 0, 64);

        /*
         * Verify that the first 64 bytes of the report data (inside
         * the quote) are SHA256(Ga||Gb||VK) || 0x00[32]
         *
         * VK = CMACkdk( 0x01 || "VK" || 0x00 || 0x80 || 0x00 )
         *
         * where || denotes concatenation.
         */

        /* Derive VK */

        cmac128(session->kdk, (unsigned char *)("\x01VK\x00\x80\x00"),
                6, session->vk);

        /* Build our plaintext */

        memcpy(msg_rdata, session->g_a, 64);
        memcpy(&msg_rdata[64], session->g_b, 64);
        memcpy(&msg_rdata[128], session->vk, 16);

        /* SHA-256 hash */

        sha256_digest(msg_rdata, 144, vfy_rdata);

        if ( CRYPTO_memcmp((void *) vfy_rdata, (void *) &r->report_data,
            64) ) {

            printf("Report verification failed.\n");
            free(b64quote);
            return 0;
        }

        /*
         * The service provider must validate that the enclave
         * report is from an enclave that they recognize. Namely,
         * that the MRSIGNER matches our signing key, and the MRENCLAVE
         * hash matches an enclave that we compiled.
         *
         * Other policy decisions might include examining ISV_SVN to
         * prevent outdated/deprecated software from successfully
         * attesting, and ensuring the TCB is not out of date.
         *
         * A real-world service provider might allow multiple ISV_SVN
         * values, but for this sample we only allow the enclave that
         * is compiled.
         */

#ifndef _WIN32
/* Windows implementation is not available yet */

        if ( ! verify_enclave_identity(config->req_mrsigner,
            config->req_isv_product_id, config->min_isvsvn,
            config->allow_debug_enclave, r) ) {

            printf("Invalid enclave.\n");
            msg4->status= NotTrusted;
        }
#endif

        printf("Copy/Paste Msg4 Below to Client\n");

        /* Serialize the members of the Msg4 structure independently */
        /* vs. the entire structure as one send_msg() */

        msgio->send_partial(&msg4->status, sizeof(msg4->status));
        msgio->send(&msg4->platformInfoBlob, sizeof(msg4->platformInfoBlob));

        /*
         * If the enclave is trusted, derive the MK and SK. Also get
         * SHA256 hashes of these so we can verify there's a shared
         * secret between us and the client.
         */

        if ( msg4->status == Trusted ) {
            unsigned char hashmk[32], hashsk[32];

            if ( debug ) printf("+++ Deriving the MK and SK\n");
            cmac128(session->kdk, (unsigned char *)("\x01MK\x00\x80\x00"),
                6, session->mk);
            cmac128(session->kdk, (unsigned char *)("\x01SK\x00\x80\x00"),
                6, session->sk);

            sha256_digest(session->mk, 16, hashmk);
            sha256_digest(session->sk, 16, hashsk);

        }

    } else {
        printf("Attestation failed\n");
        free(b64quote);
        return 0;
    }

    free(b64quote);

	return 0;
}

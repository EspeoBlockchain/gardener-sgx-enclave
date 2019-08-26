#include "EnclaveManager.h"
#include "SgxException.h"
#include "Enclave_u.h"
#include "ErrorCode.h"
#include "../Attestation/base64.h"
#include "../Attestation/byteorder.h"
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

void loadConfig(config_t *config) {
	config->apiver= IAS_API_DEF_VERSION;

	/*
	 * For demo purposes only. A production/release enclave should
	 * never allow debug-mode enclaves to attest.
	 */
	config->allow_debug_enclave= 1;

    if (!cert_load_file(&config->signing_ca)) {
        throw SgxException(SGX_ERROR_UNEXPECTED);
    }
}

int derive_kdk(EVP_PKEY *Gb, unsigned char kdk[16], sgx_ec256_public_t g_a,
	config_t *config)
{
	unsigned char *Gab_x;
	size_t slen;
	EVP_PKEY *Ga;
	unsigned char cmackey[16];

	memset(cmackey, 0, 16);

	/*
	 * Compute the shared secret using the peer's public key and a generated
	 * public/private key.
	 */

	Ga= key_from_sgx_ec256(&g_a);
	if ( Ga == NULL ) {
		crypto_perror("key_from_sgx_ec256");
		return 0;
	}

	/* The shared secret in a DH exchange is the x-coordinate of Gab */
	Gab_x= key_shared_secret(Gb, Ga, &slen);
	if ( Gab_x == NULL ) {
		crypto_perror("key_shared_secret");
		return 0;
	}

	/* We need it in little endian order, so reverse the bytes. */
	/* We'll do this in-place. */

	reverse_bytes(Gab_x, Gab_x, slen);

	/* Now hash that to get our KDK (Key Definition Key) */

	/*
	 * KDK = AES_CMAC(0x00000000000000000000000000000000, secret)
	 */

	cmac128(cmackey, Gab_x, slen, kdk);

	return 1;
}

int get_sigrl (IAS_Connection *ias, int version, sgx_epid_group_id_t gid,
	char **sig_rl, uint32_t *sig_rl_size)
{
	IAS_Request *req= NULL;
	int oops= 1;
	string sigrlstr;

	try {
		oops= 0;
		req= new IAS_Request(ias, (uint16_t) version);
	}
	catch (...) {
		oops = 1;
	}

	if (oops) {
		printf("Exception while creating IAS request object\n");
		delete req;
		return 0;
	}

        ias_error_t ret = IAS_OK;

	while (1) {

		ret =  req->sigrl(*(uint32_t *) gid, sigrlstr);

		if ( ret == IAS_UNAUTHORIZED && (ias->getSubscriptionKeyID() == IAS_Connection::SubscriptionKeyID::Primary))
		{
			// Retry with Secondary Subscription Key
			ias->SetSubscriptionKeyID(IAS_Connection::SubscriptionKeyID::Secondary);
			continue;
		}
		else if (ret != IAS_OK ) {

			delete req;
			return 0;
		}

		break;
	}


	*sig_rl= strdup(sigrlstr.c_str());
	if ( *sig_rl == NULL ) {
		delete req;
		return 0;
	}

	*sig_rl_size= (uint32_t ) sigrlstr.length();

	delete req;

	return 1;
}

/*
 * Read and process message 0 and message 1. These messages are sent by
 * the client concatenated together for efficiency (msg0||msg1).
 */

int process_msg01 (MsgIO *msgio, IAS_Connection *ias, sgx_ra_msg1_t *msg1,
	sgx_ra_msg2_t *msg2, char **sigrl, config_t *config, ra_session_t *session)
{
	struct msg01_struct {
		uint32_t msg0_extended_epid_group_id;
		sgx_ra_msg1_t msg1;
	} *msg01;
	size_t blen= 0;
	char *buffer= NULL;
	unsigned char digest[32], r[32], s[32], gb_ga[128];
	EVP_PKEY *Gb;
	int rv;

	memset(msg2, 0, sizeof(sgx_ra_msg2_t));

	/*
	 * Read our incoming message. We're using base16 encoding/hex strings
	 * so we should end up with sizeof(msg)*2 bytes.
	 */

	fprintf(stderr, "Waiting for msg0||msg1\n");

	rv= msgio->read((void **) &msg01, NULL);
	if ( rv == -1 ) {
		printf("system error reading msg0||msg1\n");
		return 0;
	} else if ( rv == 0 ) {
		printf("protocol error reading msg0||msg1\n");
		return 0;
	}

	/* According to the Intel SGX Developer Reference
	 * "Currently, the only valid extended Intel(R) EPID group ID is zero. The
	 * server should verify this value is zero. If the Intel(R) EPID group ID
	 * is not zero, the server aborts remote attestation"
	 */

	if ( msg01->msg0_extended_epid_group_id != 0 ) {
		printf("msg0 Extended Epid Group ID is not zero.  Exiting.\n");
		free(msg01);
		return 0;
	}

	// Pass msg1 back to the pointer in the caller func
	memcpy(msg1, &msg01->msg1, sizeof(sgx_ra_msg1_t));

	/* Generate our session key */

	Gb= key_generate();
	if ( Gb == NULL ) {
		printf("Could not create a session key\n");
		free(msg01);
		return 0;
	}

	/*
	 * Derive the KDK from the key (Ga) in msg1 and our session key.
	 * An application would normally protect the KDK in memory to
	 * prevent trivial inspection.
	 */

	if ( ! derive_kdk(Gb, session->kdk, msg1->g_a, config) ) {
		printf("Could not derive the KDK\n");
		free(msg01);
		return 0;
	}

	/*
 	 * Derive the SMK from the KDK
	 * SMK = AES_CMAC(KDK, 0x01 || "SMK" || 0x00 || 0x80 || 0x00)
	 */

	cmac128(session->kdk, (unsigned char *)("\x01SMK\x00\x80\x00"), 7,
		session->smk);

	/*
	 * Build message 2
	 *
	 * A || CMACsmk(A) || SigRL
	 * (148 + 16 + SigRL_length bytes = 164 + SigRL_length bytes)
	 *
	 * where:
	 *
	 * A      = Gb || SPID || TYPE || KDF-ID || SigSP(Gb, Ga)
	 *          (64 + 16 + 2 + 2 + 64 = 148 bytes)
	 * Ga     = Client enclave's session key
	 *          (32 bytes)
	 * Gb     = Service Provider's session key
	 *          (32 bytes)
	 * SPID   = The Service Provider ID, issued by Intel to the vendor
	 *          (16 bytes)
	 * TYPE   = Quote type (0= linkable, 1= linkable)
	 *          (2 bytes)
	 * KDF-ID = (0x0001= CMAC entropy extraction and key derivation)
	 *          (2 bytes)
	 * SigSP  = ECDSA signature of (Gb.x || Gb.y || Ga.x || Ga.y) as r || s
	 *          (signed with the Service Provider's private key)
	 *          (64 bytes)
	 *
	 * CMACsmk= AES-128-CMAC(A)
	 *          (16 bytes)
	 *
	 * || denotes concatenation
	 *
	 * Note that all key components (Ga.x, etc.) are in little endian
	 * format, meaning the byte streams need to be reversed.
	 *
	 * For SigRL, send:
	 *
	 *  SigRL_size || SigRL_contents
	 *
	 * where sigRL_size is a 32-bit uint (4 bytes). This matches the
	 * structure definition in sgx_ra_msg2_t
	 */

	key_to_sgx_ec256(&msg2->g_b, Gb);
	memcpy(&msg2->spid, &config->spid, sizeof(sgx_spid_t));
	msg2->quote_type= config->quote_type;
	msg2->kdf_id= 1;

	/* Get the sigrl */

	if ( ! get_sigrl(ias, config->apiver, msg1->gid, sigrl,
		&msg2->sig_rl_size) ) {

		printf("could not retrieve the sigrl\n");
		free(msg01);
		return 0;
	}

	memcpy(gb_ga, &msg2->g_b, 64);
	memcpy(session->g_b, &msg2->g_b, 64);

	memcpy(&gb_ga[64], &msg1->g_a, 64);
	memcpy(session->g_a, &msg1->g_a, 64);

	ecdsa_sign(gb_ga, 128, config->service_private_key, r, s, digest);
	reverse_bytes(&msg2->sign_gb_ga.x, r, 32);
	reverse_bytes(&msg2->sign_gb_ga.y, s, 32);

	/* The "A" component is conveniently at the start of sgx_ra_msg2_t */

	cmac128(session->smk, (unsigned char *) msg2, 148,
		(unsigned char *) &msg2->mac);

	free(msg01);

	return 1;
}

int process_msg3 (MsgIO *msgio, IAS_Connection *ias, sgx_ra_msg1_t *msg1,
	ra_msg4_t *msg4, config_t *config, ra_session_t *session)
{
	sgx_ra_msg3_t *msg3;
	size_t blen= 0;
	size_t sz;
	int rv;
	uint32_t quote_sz;
	char *buffer= NULL;
	char *b64quote;
	sgx_mac_t vrfymac;
	sgx_quote_t *q;

	/*
	 * Read message 3
	 *
	 * CMACsmk(M) || M
	 *
	 * where
	 *
	 * M = ga || PS_SECURITY_PROPERTY || QUOTE
	 *
	 */

	rv= msgio->read((void **) &msg3, &sz);
	if ( rv == -1 ) {
		printf("system error reading msg3\n");
		return 0;
	} else if ( rv == 0 ) {
		printf("protocol error reading msg3\n");
		return 0;
	}

	/*
	 * The quote size will be the total msg3 size - sizeof(sgx_ra_msg3_t)
	 * since msg3.quote is a flexible array member.
	 *
	 * Total message size is sz/2 since the income message is in base16.
	 */
	quote_sz = (uint32_t)((sz / 2) - sizeof(sgx_ra_msg3_t));

	/* Make sure Ga matches msg1 */

	if ( CRYPTO_memcmp(&msg3->g_a, &msg1->g_a, sizeof(sgx_ec256_public_t)) ) {
		printf("msg1.g_a and mgs3.g_a keys don't match\n");
		free(msg3);
		return 0;
	}

	/* Validate the MAC of M */

	cmac128(session->smk, (unsigned char *) &msg3->g_a,
		sizeof(sgx_ra_msg3_t)-sizeof(sgx_mac_t)+quote_sz,
		(unsigned char *) vrfymac);
	if ( CRYPTO_memcmp(msg3->mac, vrfymac, sizeof(sgx_mac_t)) ) {
		printf("Failed to verify msg3 MAC\n");
		free(msg3);
		return 0;
	}

	/* Encode the report body as base64 */

	b64quote= base64_encode((char *) &msg3->quote, quote_sz);
	if ( b64quote == NULL ) {
		printf("Could not base64 encode the quote\n");
		free(msg3);
		return 0;
	}
	q= (sgx_quote_t *) msg3->quote;

	/* Verify that the EPID group ID in the quote matches the one from msg1 */

	if ( memcmp(msg1->gid, &q->epid_group_id, sizeof(sgx_epid_group_id_t)) ) {
		printf("EPID GID mismatch. Attestation failed.\n");
		free(b64quote);
		free(msg3);
		return 0;
	}


	if ( get_attestation_report(ias, config->apiver, b64quote,
		msg3->ps_sec_prop, msg4, config->strict_trust) ) {

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
			free(msg3);
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

		if ( ! verify_enclave_identity(config->req_mrsigner,
			config->req_isv_product_id, config->min_isvsvn,
			config->allow_debug_enclave, r) ) {

			printf("Invalid enclave.\n");
			msg4->status= NotTrusted;
		}

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

			cmac128(session->kdk, (unsigned char *)("\x01MK\x00\x80\x00"),
				6, session->mk);
			cmac128(session->kdk, (unsigned char *)("\x01SK\x00\x80\x00"),
				6, session->sk);

			sha256_digest(session->mk, 16, hashmk);
			sha256_digest(session->sk, 16, hashsk);
		}

	} else {
		printf("Attestation failed\n");
		free(msg3);
		free(b64quote);
		return 0;
	}

	free(b64quote);
	free(msg3);

	return 1;
}

unsigned int EnclaveManager::initRemoteAttestation() {
    ra_session_t session;
    sgx_ra_msg1_t msg1;
    sgx_ra_msg2_t msg2;
    ra_msg4_t msg4;
    char *sigrl = NULL;
    MsgIO *msgio = new MsgIO();
    IAS_Connection *ias = new IAS_Connection(
        IAS_SERVER_PRODUCTION,
        0,
        "c4e96b986c714d00b6b8e656764a5b79",
        "3909408129a846fba63077f965623232"
    );
	config_t config;
	memset(&config, 0, sizeof(config));
	loadConfig(&config);

	while ( msgio->server_loop() ) {
        if (!process_msg01(msgio, ias, &msg1, &msg2, &sigrl, &config, &session)) {
            printf("error processing msg1\n");
            msgio->disconnect();
            return 0;
        }

        msgio->send_partial((void *) &msg2, sizeof(sgx_ra_msg2_t));
        msgio->send(&msg2.sig_rl, msg2.sig_rl_size);

        if (!process_msg3(msgio, ias, &msg1, &msg4, &config, &session) ) {
            printf("error processing msg3\n");
            msgio->disconnect();
            return 0;
        }
    }

	return 0;
}

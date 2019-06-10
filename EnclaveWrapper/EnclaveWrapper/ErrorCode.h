#pragma once

#define FC_OK				0x0000L
#define FC_ERR_ALLOC		0x0001L
#define FC_ERR_RAND			0x0002L
#define FC_ERR_CRYPTO		0x0003L
#define FC_ERR_AUTHTAG		0x0004L
#define FC_ERR_ENCLAVE		0x0005L

#define FC_ERR_CANCEL		0x0100L

#define FC_ERR_SGX			0x1000L
#define FC_ERR_SYS			0x2000L

#define FC_ERR_UNKNOWN		0x7FFFFFFFL
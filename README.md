# Gardener SGX enclave

This contains Intel SGX Enclave code. It will be released as DLLs and then utilised in gardener-sgx-server. It consists of 2 Visual Studio C++ projects:

- Enclave: pure SGX enclave code. It is packaged into Enclave.signed.dll
- Enclave Wrapper: wraps enclave calls to ensure error handling and provide easily interactive interface. It is packaged into EnclaveWrapper.dll

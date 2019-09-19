Build EnclaveWrapper library using `make package`

Use `./app` to test

Before compiling, you need to generate a private signing key under `Enclave/Enclave_private.pem`
Correctly buliding EnclaveWrapper in Hardware Mode requires a SGX ready machine, installing SGX SDK&PSW and using a PSW version of libsgx_urts.so . This is rather tricky so you better ask @kss-espeo for help.


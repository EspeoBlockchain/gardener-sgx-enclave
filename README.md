Build EnclaveWrapper library using g++ -shared -fPIC -o EnclaveWrapper.so App/*.o .This will be later put into Makefile

test.cpp is a program to test that libs are being correctly linked

Before compiling, you need to generate a private signing key under Enclave/Enclave_private.pem
Correctly buliding EnclaveWrapper in Hardware Mode requires a SGX ready machine, installing SGX SDK&PSW and using a PSW version of libsgx_urts.so . This is rather tricky so you better ask @kss-espeo for help.


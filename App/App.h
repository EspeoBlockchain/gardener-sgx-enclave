#ifndef __ENCLAVEWRAPPER_H__
#define __ENCLAVEWRAPPER_H__

extern "C" int generateRandom(long min, long max, long *result);
extern "C" int remoteAttestation();

#endif

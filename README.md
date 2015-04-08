# openssl-c-api-for-thali

The C function will generate a PKCS12 container which meets Thali's requirements.

Tested the API by using the openssl library in JXcore.

     g++ openssl_thali.c -lstdc++ -std=c++11 -pthread -O3 -Wno-write-strings jxcore/out/bin/libopenssl.a -ldl -o openssl_thali.o

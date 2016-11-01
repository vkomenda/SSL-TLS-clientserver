#!/bin/bash -x

CACERT=./cacert
mkdir -p $CACERT
pushd $CACERT

echo ------------ 1. Generate CA cert and key files
openssl genrsa -des3 -out ca.key 4096
openssl req -new -sha512 -x509 -nodes -days 365 -key ca.key -out ca.crt

echo ------------ 2. Generate server cert and key
openssl genrsa -des3 -out tls_server.key 4096
openssl req -new -sha512 -key tls_server.key -out tls_server.csr

echo ------------ 3. Sign server cert using CA
openssl x509 -req -days 365 -in tls_server.csr -CA ca.crt -CAkey ca.key\
        -set_serial 01 -out tls_server.crt

echo ------------ 4. Generate client cert and key
openssl genrsa -des3 -out tls_client.key 4096
openssl req -new -sha512 -key tls_client.key -out tls_client.csr

echo ------------ 5. Sign client cert using CA
openssl x509 -req -days 365 -in tls_client.csr -CA ca.crt -CAkey ca.key\
        -set_serial 01 -out tls_client.crt

popd

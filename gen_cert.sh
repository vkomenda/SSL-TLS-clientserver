CURVE=prime256v1
SERIAL=0xdeadbeef
DIGEST=sha256

mkdir -p cert
pushd cert

echo === 1. Creating the root CA cert and key
openssl ecparam -name $CURVE -genkey -param_enc named_curve -out ca.key
openssl req -new -$DIGEST -x509 -key ca.key -out ca.crt -days 730

echo === 2. Creating the server key and sign request
openssl ecparam -name $CURVE -genkey -param_enc named_curve -out server.key
openssl req -new -$DIGEST -nodes -key server.key -out server.csr

echo === 3. Signing the server cert with the root CA cert
openssl x509 -req -days 365 -in server.csr -CA ca.crt -CAkey ca.key \
        -set_serial $SERIAL -out server.crt

echo === 4. Creating the client key and sign request
openssl ecparam -name $CURVE -genkey -param_enc named_curve -out client.key
openssl req -new -$DIGEST -nodes -key client.key -out client.csr

echo === 5. Signing the client cert with the root CA cert
openssl x509 -req -days 365 -in client.csr -CA ca.crt -CAkey ca.key \
        -set_serial $SERIAL -out client.crt

echo === 6. Removing the server and client sign requests
rm server.csr client.csr

popd

openssl genrsa -out ca.key 2048
openssl rsa -in ca.key -pubout -out ca.pubkey
openssl req -new -x509 -days 3650 -key ca.key -out ca.cert

openssl genrsa -out server.key 2048
openssl rsa -in server.key -pubout -out server.pubkey
openssl req -new -key server.key -out server.csr
openssl x509 -req -days 3650 -in server.csr -CA ca.cert -CAkey ca.key -CAcreateserial -out server.cert

openssl genrsa -out client.key 2048
openssl rsa -in client.key -pubout -out client.pubkey
openssl req -new -key client.key -out client.csr
openssl x509 -req -days 3650 -in client.csr -CA ca.cert -CAkey ca.key -CAcreateserial -out client.cert
openssl genrsa -out ca.pem 2048
openssl rsa -in ca.pem -pubout -out ca.pubkey
openssl req -new -x509 -days 3650 -key ca.pem -out ca.cert

openssl genrsa -out server.pem 2048
openssl rsa -in server.pem -pubout -out server.pubkey
openssl req -new -key server.pem -out server.csr
openssl x509 -req -days 3650 -in server.csr -CA ca.cert -CAkey ca.pem -CAcreateserial -out server.cert

openssl genrsa -out client.pem 2048
openssl rsa -in client.pem -pubout -out client.pubkey
openssl req -new -key client.pem -out client.csr
openssl x509 -req -days 3650 -in client.csr -CA ca.cert -CAkey ca.pem -CAcreateserial -out client.cert
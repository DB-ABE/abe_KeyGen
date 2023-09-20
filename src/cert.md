openssl genrsa -out ca.pem 2048
openssl rsa -in ca.pem -pubout -out ca.pubkey
openssl req -new -x509 -days 3650 -key ca.pem -out cacert.pem

openssl genrsa -out server.pem 2048
openssl rsa -in server.pem -pubout -out server.pubkey
openssl req -new -key server.pem -out server.csr
openssl x509 -req -days 3650 -in server.csr -CA cacert.pem -CAkey ca.pem -CAcreateserial -out servercert.pem

openssl genrsa -out client.pem 2048
openssl rsa -in client.pem -pubout -out client.pubkey
openssl req -new -key client.pem -out client.csr
openssl x509 -req -days 3650 -in client.csr -CA cacert.pem -CAkey ca.pem -CAcreateserial -out clientcert.pem
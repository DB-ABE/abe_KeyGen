openssl genrsa -out CA_prikey.pem 2048
openssl rsa -in CA_prikey.pem -pubout -out CA_pubkey.pem
openssl req -new -x509 -days 3650 -key CA_prikey.pem -out CA_cert.pem

openssl genrsa -out KMS_prikey.pem 2048
openssl rsa -in KMS_prikey.pem -pubout -out KMS_pubkey.pem
openssl req -new -key KMS_prikey.pem -out KMS.csr
openssl x509 -req -days 3650 -in KMS.csr -CA CA_cert.pem -CAkey CA_prikey.pem -CAcreateserial -out KMS_cert.pem

openssl genrsa -out DB_prikey.pem 2048
openssl rsa -in DB_prikey.pem -pubout -out DB_pubkey.pem
openssl req -new -key DB_prikey.pem -out DB.csr
openssl x509 -req -days 3650 -in DB.csr -CA CA_cert.pem -CAkey CA_prikey.pem -CAcreateserial -out DB_cert.pem
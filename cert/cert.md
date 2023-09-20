//root
gmssl sm2keygen -pass 123456 -out rootcakey.pem
gmssl certgen -C CN -ST Beijing -L Haidian -O PKU -OU CS -CN ROOTCA -days 3650 \
-key rootcakey.pem -pass 123456 \
-out rootcacert.pem \
-ca \
-key_usage keyCertSign

//-key_usage cRLSign \
//-crl_http_uri http://pku.edu.cn/ca.crl -ca_issuers_uri http://pku.edu.cn/ca.crt -ocsp_uri http://ocsp.pku.edu.cn
gmssl certparse -in rootcacert.pem

//ca
gmssl sm2keygen -pass 123456 -out CA/cakey.pem
gmssl reqgen -C CN -ST WuHan -L Dongxihuqu -O PKU -OU CS -CN "Sub CA" -key CA/cakey.pem -pass 123456 -out req/careq.pem
gmssl reqsign -in req/careq.pem -days 365 -key_usage keyCertSign -path_len_constraint 0 -cacert rootcacert.pem -key rootcakey.pem -pass 123456 -out CA/cacert.pem
gmssl certparse -in CA/cacert.pem


//sign_database
gmssl sm2keygen -pass 123456 -out key_sign/signkey_1.pem -pubout key_ver/verkey_1.pem
gmssl reqgen -C CN -ST WuHan -L Dongxihuqu -O PKU -OU CS -CN database -key key_sign/signkey_1.pem -pass 123456 -out req/signreq_1.pem
gmssl reqsign -in req/signreq_1.pem -days 365 -key_usage digitalSignature -cacert CA/cacert.pem -key CA/cakey.pem -pass 123456 -out cert_sign/signcert_1.pem
gmssl certparse -in cert_sign/signcert_1.pem

//enc_database
gmssl sm2keygen -pass 123456 -out key_dec/deckey_1.pem -pubout key_enc/enckey_1.pem
gmssl reqgen -C CN -ST WuHan -L Dongxihuqu -O PKU -OU CS -CN database -key key_enc/enckey_1.pem -pass 123456 -out req/encreq_1.pem
gmssl reqsign -in req/encreq_1.pem -days 365 -key_usage keyEncipherment -cacert CA/cacert.pem -key CA/cakey.pem -pass 123456 -out cert_enc/enccert_1.pem
gmssl certparse -in cert_enc/enccert_1.pem


//sign_zhangsan
gmssl sm2keygen -pass 123456 -out key_sign/signkey_2.pem -pubout key_ver/verkey_2.pem
gmssl reqgen -C CN -ST WuHan -L Dongxihuqu -O PKU -OU CS -CN zhangsan -key key_sign/signkey_2.pem -pass 123456 -out req/signreq_2.pem
gmssl reqsign -in req/signreq_2.pem -days 365 -key_usage digitalSignature -cacert CA/cacert.pem -key CA/cakey.pem -pass 123456 -out cert_sign/signcert_2.pem
gmssl certparse -in cert_sign/signcert_2.pem

//enc_zhangsan
gmssl sm2keygen -pass 123456 -out key_dec/deckey_2.pem -pubout key_enc/enckey_2.pem
gmssl reqgen -C CN -ST WuHan -L Dongxihuqu -O PKU -OU CS -CN zhangsan -key key_enc/enckey_2.pem -pass 123456 -out req/encreq_2.pem
gmssl reqsign -in req/encreq_2.pem -days 365 -key_usage keyEncipherment -cacert CA/cacert.pem -key CA/cakey.pem -pass 123456 -out cert_enc/enccert_2.pem
gmssl certparse -in cert_enc/enccert_2.pem


//verify single-cert-CA
//database
gmssl certverify -in cert_sign/signcert_1.pem -cacert CA/cacert.pem
gmssl certverify -in cert_enc/enccert_1.pem -cacert CA/cacert.pem

//zhangsan
gmssl certverify -in cert_sign/signcert_2.pem -cacert CA/cacert.pem
gmssl certverify -in cert_enc/enccert_2.pem -cacert CA/cacert.pem


//verify double-cert-CA
//database
cat cert_sign/signcert_1.pem > test/dbl_certs.pem
cat cert_enc/enccert_1.pem >> test/dbl_certs.pem
gmssl certverify -double_certs -in test/dbl_certs.pem -cacert CA/cacert.pem

//zhangsan
cat cert_sign/signcert_2.pem > test/dbl_certs.pem
cat cert_enc/enccert_2.pem >> test/dbl_certs.pem
gmssl certverify -double_certs -in test/dbl_certs.pem -cacert CA/cacert.pem


//verify single-cert-CA-root
//database
cat cert_sign/signcert_1.pem > test/certs.pem
cat CA/cacert.pem >> test/certs.pem
gmssl certverify -in test/certs.pem -cacert rootcacert.pem

cat cert_enc/enccert_1.pem > test/certs.pem
cat CA/cacert.pem >> test/certs.pem
gmssl certverify -in test/certs.pem -cacert rootcacert.pem

//zhangsan
cat cert_sign/signcert_2.pem > test/certs.pem
cat CA/cacert.pem >> test/certs.pem
gmssl certverify -in test/certs.pem -cacert rootcacert.pem

cat cert_enc/enccert_2.pem > test/certs.pem
cat CA/cacert.pem >> test/certs.pem
gmssl certverify -in test/certs.pem -cacert rootcacert.pem


//verify double-cert
//database
cat cert_sign/signcert_1.pem > test/dbl_certs.pem
cat cert_enc/enccert_1.pem >> test/dbl_certs.pem
cat CA/cacert.pem >> test/dbl_certs.pem
gmssl certverify -double_certs -in test/dbl_certs.pem -cacert rootcacert.pem

//zhangsan
cat cert_sign/signcert_2.pem > test/dbl_certs.pem
cat cert_enc/enccert_2.pem >> test/dbl_certs.pem
cat CA/cacert.pem >> test/dbl_certs.pem
gmssl certverify -double_certs -in test/dbl_certs.pem -cacert rootcacert.pem
//check -crl
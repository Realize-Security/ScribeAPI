#!/bin/bash

PRIVKEY=./certs/privkey.pem
FULLCHAIN=./certs/fullchain.pem

/bin/rm -rf certs
/bin/mkdir certs
openssl genrsa -out $PRIVKEY 2048
openssl req -new -key $PRIVKEY -out csr.pem
openssl x509 -req -in csr.pem -signkey $PRIVKEY -out $FULLCHAIN -days 365
/bin/rm csr.pem


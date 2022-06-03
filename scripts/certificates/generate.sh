mkdir certificates

openssl genrsa -out certificates/CA.key 2048
openssl req -x509 -new -key certificates/CA.key -out certificates/CA.crt -days 730 -subj "//CN=0xARYA"

openssl genrsa -out certificates/localhost.key 2048
openssl req -new -out certificates/localhost.req -key certificates/localhost.key -subj "//CN=localhost"
openssl x509 -req -in certificates/localhost.req -out certificates/localhost.crt -CAkey certificates/CA.key -CA certificates/CA.crt -days 365 -CAcreateserial -extfile ./certificate.ext -CAserial serial

cat certificates/localhost.key certificates/localhost.crt > certificates/localhost.pem
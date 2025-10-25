**OpenSSL** can be used through the command line to perform various cryptographic operations, such as generating and managing SSL/TLS certificates, encrypting and decrypting data, creating digital signatures, and more. It supports a wide range of cryptographic algorithms and protocols.

One common and straightforward use case of OpenSSL is generating a self-signed SSL certificate for testing or development purposes. Here's an example of how to generate a self-signed certificate using OpenSSL:

| Option                      | Description |
|-----------------------------|-------------|
| **`req`**                    | This subcommand is used for certificate requests and management. |
| **`-x509`**                  | This option tells OpenSSL to create a self-signed certificate instead of a certificate signing request (CSR). |
| **`-newkey rsa:2048`**       | It generates a new RSA private key of 2048 bits. |
| **`-keyout mykey.pem`**      | Specifies the output file for the generated private key (mykey.pem). |
| **`-out mycert.pem`**        | Specifies the output file for the generated self-signed certificate (mycert.pem). |
| **`-days 365`**              | Sets the validity period of the certificate to 365 days. |

```bash
openssl req -x509 -newkey rsa:2048 -keyout mykey.pem -out mycert.pem -days 365
```


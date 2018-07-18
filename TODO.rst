TODO
====
- Modify COMODO_CLIENT_PUBLIC_CERT and COMODO_CLIENT_PRIVATE_KEY to consume the actual certificates not the path to the certificates.
    - Would require consuming ENV var into a file location as requests uses openssl which expects a file.
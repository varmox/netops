Files here are git-ignored and mounted read-only into the backend at /secrets.

- `mikrotik_id_rsa`: private SSH key (RSA) of the router user that runs `/export`. RouterOS 7.16 could only verify RSA signatures, so stay with RSA.

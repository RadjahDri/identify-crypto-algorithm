# Crypto algorithm identifiers suite

## Description

This suite of tools identifies cryptographic algorithms (encryption, hash) via input and output data.

## Encryption algorithm identifier: identityEncryptionAlgorithm.py

### Description

This tool is used to identify encryption algorithms during reverse engineering analysis. The method is to test a list of encryption algorithms with parameters retrieved during the analysis: encrypted data, decrypted data, keys and IV/nonce.

### Utilisation

The script takes as input the file paths containing the encrypted data, decrypted data, keys, IV/nonce and a parameter to indicate whether the action is encryption or decryption.

## Hash algorithm identifier: identityHashAlgorithm.py

### Description

This tool is used to identify hash algorithms during reverse engineering analysis. The method is to test a list of hash algorithms with parameters retrieved during the analysis: input and output data.

### Utilisation

The script takes as input the file paths containing the input data and output data.
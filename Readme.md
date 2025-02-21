# Crypto algorithm identifiers suite

## Description

This suite of tools identifies cryptographic algorithms (encryption, hash) via input and output data.

## Encryption algorithm identifier: identityEncryptionAlgorithm.py

### Description

This tool is used to identify encryption algorithms during reverse engineering analysis. The method is to test a list of encryption algorithms with parameters retrieved during the analysis: encrypted data, decrypted data, keys and IV/nonce.

### Usage

The script takes as input the file paths containing the encrypted data, decrypted data, keys, IV/nonce and a parameter to indicate whether the action is encryption or decryption.

```
usage: identityEncryptionAlgorithm.py [-h] -e ENCRYPTEDFILEPATH -d DECRYPTEDFILEPATH -k KEYFILEPATH [-i IVFILEPATH] [-a {Encrypt,Decrypt}]

identifyEncryptionAlgorithm - Encryption algorithm identifier from input and output data

options:
  -h, --help            show this help message and exit
  -e ENCRYPTEDFILEPATH, --encryptedFilePath ENCRYPTEDFILEPATH
                        Encrypted data file path
  -d DECRYPTEDFILEPATH, --decryptedFilePath DECRYPTEDFILEPATH
                        Decrypted data file path
  -k KEYFILEPATH, --keyFilePath KEYFILEPATH
                        Key file path
  -i IVFILEPATH, --ivFilePath IVFILEPATH
                        IV/Nonce file path
  -a {Encrypt,Decrypt}, --action {Encrypt,Decrypt}
                        Action: Encrypt or Decrypt
```

## Hash algorithm identifier: identityHashAlgorithm.py

### Description

This tool is used to identify hash algorithms during reverse engineering analysis. The method is to test a list of hash algorithms with parameters retrieved during the analysis: input and output data.

### Usage

The script takes as input the file paths containing the input data and output data.
```
usage: identityHashAlgorithm.py [-h] -i INPUTFILEPATH -o OUTPUTFILEPATH

identifyHashAlgorithm - Hash algorithm identifier from input and output data

options:
  -h, --help            show this help message and exit
  -i INPUTFILEPATH, --inputFilePath INPUTFILEPATH
                        Input data file path
  -o OUTPUTFILEPATH, --outputFilePath OUTPUTFILEPATH
                        Output data file path
```
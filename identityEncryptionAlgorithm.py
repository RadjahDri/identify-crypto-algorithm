import argparse

from Cryptodome.Cipher import AES
from Cryptodome.Cipher import ARC2
from Cryptodome.Cipher import ARC4
from Cryptodome.Cipher import Blowfish
from Cryptodome.Cipher import CAST
from Cryptodome.Cipher import ChaCha20
from Cryptodome.Cipher import ChaCha20_Poly1305
from Cryptodome.Cipher import DES
from Cryptodome.Cipher import DES3
from Cryptodome.Cipher import Salsa20


### Constants

### Classes
class CustomException(Exception):
    def __init__(self, msg: str):
        self.msg = msg

class ParamException(Exception):
    def __init__(self, msg: str):
        self.msg = msg


### Functions
def testAgls(encryptedData, decryptedData, keyData, ivData, isEncrypt):
    algs = {}
    algs.update(addAesAlgs(keyData, ivData, isEncrypt))
    algs.update(addArc2Algs(keyData, ivData, isEncrypt))
    algs.update(addArc4Algs(keyData, ivData, isEncrypt))
    algs.update(addBlowfishAlgs(keyData, ivData, isEncrypt))
    algs.update(addCastAlgs(keyData, ivData, isEncrypt))
    algs.update(addChaCha20Algs(keyData, ivData, isEncrypt))
    algs.update(addChaCha20Poly1305Algs(keyData, ivData, isEncrypt))
    algs.update(addDesAlgs(keyData, ivData, isEncrypt))
    algs.update(addDes3Algs(keyData, ivData, isEncrypt))
    algs.update(addSalsa20Algs(keyData, ivData, isEncrypt))
        
    testedAlgs = {}
    for algName in algs.keys():
        if(testAlg(algs[algName], isEncrypt, encryptedData, decryptedData)):
            testedAlgs[algName] = True
        else:
            testedAlgs[algName] = False

    return testedAlgs


def testAlg(alg, isEncrypt, encryptedData, decryptedData):
    if(isEncrypt):
        workedData = alg.encrypt(decryptedData)
        return workedData == encryptedData
    else:
        workedData = alg.decrypt(encryptedData)
        return workedData == decryptedData
    

def addAesAlgs(keyData: bytearray, ivData: bytearray, isEncrypt: bool):
    algs = {}
    keyLen = len(keyData)
    if(keyLen in [0x10, 0x18, 0x20]):
        if(ivData):
            ivLen = len(ivData)

            if(ivLen == 0x10):
                algs["AES CBC"] = AES.new(keyData, AES.MODE_CBC, iv=ivData)
                algs["AES CFB"] = AES.new(keyData, AES.MODE_CFB, iv=ivData)
                algs["AES OFB"] = AES.new(keyData, AES.MODE_OFB, iv=ivData)
                
                if(isEncrypt):
                    algs["AES OPENPGP"] = AES.new(keyData, AES.MODE_OPENPGP, iv=ivData)

            if(ivLen == 18 and not isEncrypt):
                algs["AES OPENPGP"] = AES.new(keyData, AES.MODE_OPENPGP, iv=ivData)

            if(6 < ivLen and ivLen <= 13):
                algs["AES CCM"] = AES.new(keyData, AES.MODE_CCM, nonce=ivData)
                
            if(ivLen <= 15):
                algs["AES OCB"] = AES.new(keyData, AES.MODE_OCB, nonce=ivData)

            if(ivLen <= 15):
                algs["AES CTR"] = AES.new(keyData, AES.MODE_CTR, nonce=ivData)

            algs["AES EAX"] = AES.new(keyData, AES.MODE_EAX, nonce=ivData)
            algs["AES GCM"] = AES.new(keyData, AES.MODE_GCM, nonce=ivData)

        else:
            algs["AES CBC"] = AES.new(keyData, AES.MODE_CBC, iv=b"\x00"*0x10)
            algs["AES CFB"] = AES.new(keyData, AES.MODE_CFB, iv=b"\x00"*0x10)
            algs["AES OFB"] = AES.new(keyData, AES.MODE_OFB, iv=b"\x00"*0x10)
            if(isEncrypt):
                algs["AES OPENPGP"] = AES.new(keyData, AES.MODE_OPENPGP, iv=b"\x00"*16)
            else:
                algs["AES OPENPGP"] = AES.new(keyData, AES.MODE_OPENPGP, iv=b"\x00"*18)

            algs["AES CTR"] = AES.new(keyData, AES.MODE_CTR, nonce=b"")

            algs["AES ECB"] = AES.new(keyData, AES.MODE_ECB)

    return algs
    

def addArc2Algs(keyData: bytearray, ivData: bytearray, isEncrypt: bool):
    algs = {}
    keyLen = len(keyData)
    if(5 <= keyLen and keyLen <= 128):
        if(ivData):
            ivLen = len(ivData)
            if(ivLen == 8):
                algs["ARC2 CBC"] = ARC2.new(keyData, ARC2.MODE_CBC, iv=ivData)
                algs["ARC2 CFB"] = ARC2.new(keyData, ARC2.MODE_CFB, iv=ivData)
                algs["ARC2 OFB"] = ARC2.new(keyData, ARC2.MODE_OFB, iv=ivData)

                if(isEncrypt):
                    algs["ARC2 OPENPGP"] = ARC2.new(keyData, ARC2.MODE_OPENPGP, iv=ivData)
            
            if(ivLen == 10 and not isEncrypt):
                    algs["ARC2 OPENPGP"] = ARC2.new(keyData, ARC2.MODE_OPENPGP, iv=ivData)

            if(ivLen <= 7):
                algs["ARC2 CTR"] = ARC2.new(keyData, ARC2.MODE_CTR, nonce=ivData)

            algs["ARC2 EAX"] = ARC2.new(keyData, ARC2.MODE_EAX, nonce=ivData)

        else:
            algs["ARC2 CBC"] = ARC2.new(keyData, ARC2.MODE_CBC, iv=b"\x00"*8)
            algs["ARC2 CFB"] = ARC2.new(keyData, ARC2.MODE_CFB, iv=b"\x00"*8)
            algs["ARC2 OFB"] = ARC2.new(keyData, ARC2.MODE_OFB, iv=b"\x00"*8)
            if(isEncrypt):
                algs["ARC2 OPENPGP"] = ARC2.new(keyData, ARC2.MODE_OPENPGP, iv=b"\x00"*8)
            else:
                algs["ARC2 OPENPGP"] = ARC2.new(keyData, ARC2.MODE_OPENPGP, iv=b"\x00"*10)
            algs["ARC2 CTR"] = ARC2.new(keyData, ARC2.MODE_CTR, nonce=b"")

    return algs


def addArc4Algs(keyData: bytearray, ivData: bytearray, isEncrypt: bool):
    algs = {}
    keyLen = len(keyData)
    if(1 <= keyLen and keyLen <= 256):
        if(not ivData):
            algs["ARC4"] = ARC4.new(keyData)

    return algs


def addBlowfishAlgs(keyData: bytearray, ivData: bytearray, isEncrypt: bool):
    algs = {}
    keyLen = len(keyData)
    if(5 <= keyLen and keyLen <= 56):
        if(ivData):
            ivLen = len(ivData)

            if(ivLen == 8):
                algs["Blowfish CBC"] = Blowfish.new(keyData, Blowfish.MODE_CBC, iv=ivData)
                algs["Blowfish CFB"] = Blowfish.new(keyData, Blowfish.MODE_CFB, iv=ivData)
                algs["Blowfish OFB"] = Blowfish.new(keyData, Blowfish.MODE_OFB, iv=ivData)

                if(isEncrypt):
                    algs["Blowfish OPENPGP"] = Blowfish.new(keyData, Blowfish.MODE_OPENPGP, iv=ivData)

            if(ivLen == 10 and not isEncrypt):
                algs["Blowfish OPENPGP"] = Blowfish.new(keyData, Blowfish.MODE_OPENPGP, iv=ivData)

            algs["Blowfish EAX"] = Blowfish.new(keyData, Blowfish.MODE_EAX, nonce=ivData)

            if(ivLen <= 7):
                algs["Blowfish CTR"] = Blowfish.new(keyData, Blowfish.MODE_CTR, nonce=ivData)

        else:
            algs["Blowfish CBC"] = Blowfish.new(keyData, Blowfish.MODE_CBC, iv=b"\x00"*8)
            algs["Blowfish CFB"] = Blowfish.new(keyData, Blowfish.MODE_CFB, iv=b"\x00"*8)
            algs["Blowfish OFB"] = Blowfish.new(keyData, Blowfish.MODE_OFB, iv=b"\x00"*8)
            if(isEncrypt):
                algs["Blowfish OPENPGP"] = Blowfish.new(keyData, Blowfish.MODE_OPENPGP, iv=b"\x00"*8)
            else:
                algs["Blowfish OPENPGP"] = Blowfish.new(keyData, Blowfish.MODE_OPENPGP, iv=b"\x00"*10)

            algs["Blowfish CTR"] = Blowfish.new(keyData, Blowfish.MODE_CTR, nonce=b"")

    return algs


def addCastAlgs(keyData: bytearray, ivData: bytearray, isEncrypt: bool):
    algs = {}
    keyLen = len(keyData)
    if(5 <= keyLen and keyLen <= 16):
        if(ivData):
            ivLen = len(ivData)
            if(ivLen == 8):
                algs["CAST CBC"] = CAST.new(keyData, CAST.MODE_CBC, iv=ivData)
                algs["CAST CFB"] = CAST.new(keyData, CAST.MODE_CFB, iv=ivData)
                algs["CAST OFB"] = CAST.new(keyData, CAST.MODE_OFB, iv=ivData)

                if(isEncrypt):
                    algs["CAST OPENPGP"] = CAST.new(keyData, CAST.MODE_OPENPGP, iv=ivData)

            if(ivLen == 10 and not isEncrypt):
                algs["CAST OPENPGP"] = CAST.new(keyData, CAST.MODE_OPENPGP, iv=ivData)

            algs["CAST EAX"] = CAST.new(keyData, CAST.MODE_EAX, nonce=ivData)
            if(ivLen <= 7):
                algs["CAST CTR"] = CAST.new(keyData, CAST.MODE_CTR, nonce=ivData)

        else:
            algs["CAST CBC"] = CAST.new(keyData, CAST.MODE_CBC, iv=b"\x00"*8)
            algs["CAST CFB"] = CAST.new(keyData, CAST.MODE_CFB, iv=b"\x00"*8)
            algs["CAST OFB"] = CAST.new(keyData, CAST.MODE_OFB, iv=b"\x00"*8)
            if(isEncrypt):
                algs["CAST OPENPGP"] = CAST.new(keyData, CAST.MODE_OPENPGP, iv=b"\x00"*8)
            else:
                algs["CAST OPENPGP"] = CAST.new(keyData, CAST.MODE_OPENPGP, iv=b"\x00"*10)
            algs["CAST CTR"] = CAST.new(keyData, CAST.MODE_CTR, nonce=b"")

    return algs


def addChaCha20Algs(keyData: bytearray, ivData: bytearray, isEncrypt: bool):
    algs = {}
    keyLen = len(keyData)
    if(keyLen == 0x20):
        if(ivData):
            ivLen = len(ivData)
            if(ivLen in [8, 12, 24]):
                algs["ChaCha20"] = ChaCha20.new(keyData, nonce=ivData)

    return algs


def addChaCha20Poly1305Algs(keyData: bytearray, ivData: bytearray, isEncrypt: bool):
    algs = {}
    keyLen = len(keyData)
    if(keyLen == 0x20):
        if(ivData):
            ivLen = len(ivData)
            if(ivLen in [8, 12, 24]):
                algs["ChaCha20_Poly1305"] = ChaCha20_Poly1305.new(keyData, nonce=ivData)

    return algs


def addDesAlgs(keyData: bytearray, ivData: bytearray, isEncrypt: bool):
    algs = {}
    keyLen = len(keyData)
    if(keyLen == 8):
        if(ivData):
            ivLen = len(ivData)
            if(ivLen == 8):
                algs["DES CBC"] = DES.new(keyData, DES.MODE_CBC, iv=ivData)
                algs["DES CFB"] = DES.new(keyData, DES.MODE_CFB, iv=ivData)
                algs["DES OFB"] = DES.new(keyData, DES.MODE_OFB, iv=ivData)

                if(isEncrypt):
                    algs["DES OPENPGP"] = DES.new(keyData, DES.MODE_OPENPGP, iv=ivData)

            if(ivLen == 10 and not isEncrypt):
                algs["DES OPENPGP"] = DES.new(keyData, DES.MODE_OPENPGP, iv=ivData)

            algs["DES EAX"] = DES.new(keyData, DES.MODE_EAX, nonce=ivData)
            if(ivLen <= 7):
                algs["DES CTR"] = DES.new(keyData, DES.MODE_CTR, nonce=ivData)

        else:
            algs["DES CBC"] = DES.new(keyData, DES.MODE_CBC, iv=b"\x00"*8)
            algs["DES CFB"] = DES.new(keyData, DES.MODE_CFB, iv=b"\x00"*8)
            algs["DES OFB"] = DES.new(keyData, DES.MODE_OFB, iv=b"\x00"*8)
            if(isEncrypt):
                algs["DES OPENPGP"] = DES.new(keyData, DES.MODE_OPENPGP, iv=b"\x00"*8)
            else:
                algs["DES OPENPGP"] = DES.new(keyData, DES.MODE_OPENPGP, iv=b"\x00"*10)
            algs["DES CTR"] = DES.new(keyData, DES.MODE_CTR, nonce=b"")

    return algs


def addDes3Algs(keyData: bytearray, ivData: bytearray, isEncrypt: bool):
    algs = {}
    keyLen = len(keyData)
    try:
        if(keyLen in [16, 24]):
            if(ivData):
                ivLen = len(ivData)
                if(ivLen == 8):
                    algs["DES3 CBC"] = DES3.new(keyData, DES3.MODE_CBC, iv=ivData)
                    algs["DES3 CFB"] = DES3.new(keyData, DES3.MODE_CFB, iv=ivData)
                    algs["DES3 OFB"] = DES3.new(keyData, DES3.MODE_OFB, iv=ivData)

                    if(isEncrypt):
                        algs["DES3 OPENPGP"] = DES3.new(keyData, DES3.MODE_OPENPGP, iv=ivData)

                if(ivLen == 10 and not isEncrypt):
                    algs["DES3 OPENPGP"] = DES3.new(keyData, DES3.MODE_OPENPGP, iv=ivData)

                algs["DES3 EAX"] = DES3.new(keyData, DES3.MODE_EAX, nonce=ivData)
                if(ivLen <= 7):
                    algs["DES3 CTR"] = DES3.new(keyData, DES3.MODE_CTR, nonce=ivData)

            else:
                algs["DES3 CBC"] = DES3.new(keyData, DES3.MODE_CBC, iv=b"\x00"*8)
                algs["DES3 CFB"] = DES3.new(keyData, DES3.MODE_CFB, iv=b"\x00"*8)
                algs["DES3 OFB"] = DES3.new(keyData, DES3.MODE_OFB, iv=b"\x00"*8)
                if(isEncrypt):
                    algs["DES3 OPENPGP"] = DES3.new(keyData, DES3.MODE_OPENPGP, iv=b"\x00"*8)
                else:
                    algs["DES3 OPENPGP"] = DES3.new(keyData, DES3.MODE_OPENPGP, iv=b"\x00"*10)
                algs["DES3 CTR"] = DES3.new(keyData, DES3.MODE_CTR, nonce=b"")
    except ValueError:
        pass

    return algs


def addSalsa20Algs(keyData: bytearray, ivData: bytearray, isEncrypt: bool):
    algs = {}
    keyLen = len(keyData)
    if(keyLen in [16, 32]):
        if(ivData):
            ivLen = len(ivData)
            if(ivLen == 8):
                algs["Salsa20"] = Salsa20.new(keyData, nonce=ivData)
        else:
            algs["Salsa20"] = Salsa20.new(keyData, nonce=b"\x00" * 8)

    return algs



### MAIN
def parseArgument():
    parser = argparse.ArgumentParser(description='identifyEncryptionAlgorithm - Encryption algorithm identifier from input and output data')
    parser.add_argument('-e', '--encryptedFilePath', help='Encrypted data file path', type=str, required=True)
    parser.add_argument('-d', '--decryptedFilePath', help='Decrypted data file path', type=str, required=True)
    parser.add_argument('-k', '--keyFilePath', help='Key file path', type=str, required=True)
    parser.add_argument('-i', '--ivFilePath', help='IV/Nonce file path', type=str, required=False, default=None)
    parser.add_argument('-a', '--action', help='Action: Encrypt or Decrypt', type=str, choices=["Encrypt", "Decrypt"])

    return parser.parse_args()


def main(encryptedFilePath: str, decryptedFilePath: str, keyFilePath: str, ivFilePath: str, action: str):
    with open(encryptedFilePath, 'rb') as encryptedFile:
        encryptedData = encryptedFile.read()

    with open(decryptedFilePath, 'rb') as decryptedFile:
        decryptedData = decryptedFile.read()

    with open(keyFilePath, 'rb') as keyFile:
        keyData = keyFile.read()

    if(ivFilePath):
        with open(ivFilePath, 'rb') as ivFile:
            ivData = ivFile.read()

        if(not ivData):
            print('[-] Param error: "IV file is empty"')
            return 1
    else: 
        ivData = None

    if(not keyData):
        print('[-] Param error: "Key file is empty"')
        return 1

    isEncrypt = (action == "Encrypt")

    testedAgls = testAgls(encryptedData, decryptedData, keyData, ivData, isEncrypt)

    print("[+] Tested algorithms:")
    for algName in testedAgls.keys():
        print(f"[+] \t {algName}")

    matchAlgs = list(map(lambda x: x[0], filter(lambda x: x[1], testedAgls.items())))
    if(len(matchAlgs)):
        print(f"[+] Algorithms match :")
        for algName in matchAlgs:
            print(f"[+] \t{algName}")
    else:
        print("[+] No algotithe match")
    
    return 0

if(__name__ == "__main__"):
    args = parseArgument()

    exit(main(args.encryptedFilePath, args.decryptedFilePath, args.keyFilePath, args.ivFilePath, args.action))
import argparse

from Cryptodome.Hash import BLAKE2b
from Cryptodome.Hash import BLAKE2s
from Cryptodome.Hash import MD2
from Cryptodome.Hash import MD4
from Cryptodome.Hash import MD5
from Cryptodome.Hash import RIPEMD
from Cryptodome.Hash import RIPEMD160
from Cryptodome.Hash import SHA1
from Cryptodome.Hash import SHA224
from Cryptodome.Hash import SHA256
from Cryptodome.Hash import SHA384
from Cryptodome.Hash import SHA512
from Cryptodome.Hash import SHA3_224
from Cryptodome.Hash import SHA3_256
from Cryptodome.Hash import SHA3_384
from Cryptodome.Hash import SHA3_512
from Cryptodome.Hash import keccak


### Constants

### Classes
class CustomException(Exception):
    def __init__(self, msg: str):
        self.msg = msg

class ParamException(Exception):
    def __init__(self, msg: str):
        self.msg = msg


### Functions
def testAgls(inputData, outputData):
    algs = {}

    if(len(outputData) == 0x10):
        algs["MD2"] = MD2.new()
        algs["MD4"] = MD4.new()
        algs["MD5"] = MD5.new()

    if(len(outputData) == 0x14):
        algs["RIPEMD"] = RIPEMD.new()
        algs["RIPEMD160"] = RIPEMD160.new()
        algs["SHA1"] = SHA1.new()

    if(len(outputData) == 0x1C):
        algs["RIPEMD"] = RIPEMD.new()
        algs["SHA224"] = SHA224.new()
        algs["SHA3_224"] = SHA3_224.new()
        algs["SHA3_256"] = SHA3_224.new()
        algs["keccak 28"] = keccak.new(digest_bytes=28)

    if(len(outputData) == 0x20):
        algs["BLAKE2s"] = BLAKE2s.new()
        algs["RIPEMD160"] = RIPEMD160.new()
        algs["SHA256"] = SHA256.new()
        algs["keccak 32"] = keccak.new(digest_bytes=32)

    if(len(outputData) == 0x30):
        algs["SHA384"] = SHA384.new()
        algs["SHA3_384"] = SHA3_384.new()
        algs["keccak 48"] = keccak.new(digest_bytes=48)

    if(len(outputData) == 0x40):
        algs["BLAKE2b"] = BLAKE2b.new()
        algs["SHA512"] = SHA512.new()
        algs["SHA3_512"] = SHA3_512.new()
        algs["keccak 64"] = keccak.new(digest_bytes=64)

    
        
    testedAlgs = {}
    for algName in algs.keys():
        if(testAlg(algs[algName], inputData, outputData)):
            testedAlgs[algName] = True
        else:
            testedAlgs[algName] = False

    return testedAlgs


def testAlg(alg, inputData, outputData):
    hash = alg.new()
    hash.update(inputData)
    return hash.digest() == outputData



### Main
def parseArgument():
    parser = argparse.ArgumentParser(description='identifyHashAlgorithm - Hash algorithm identifier from input and output data')
    parser.add_argument('-i', '--inputFilePath', help='Input data file path', type=str, required=True)
    parser.add_argument('-o', '--outputFilePath', help='Output data file path', type=str, required=True)
    
    return parser.parse_args()


def main(inputFilePath: str, outputFilePath: str):
    with open(inputFilePath, 'rb') as inputFile:
        inputData = inputFile.read()

    with open(outputFilePath, 'rb') as decryptedFile:
        outputData = decryptedFile.read()

    testedAgls = testAgls(inputData, outputData)

    print("[+] Tested algorithms:")
    for algName in testedAgls.keys():
        print(f"[+] \t {algName}")

    matchAlgs = list(map(lambda x: x[0], filter(lambda x: x[1], testedAgls.items())))
    if(len(matchAlgs)):
        print(f"[+] Algorithms match :")
        for algName in matchAlgs:
            print(f"[+] \t{algName}")
    else:
        print("[+] No algotith match")
    
    return 0


if(__name__ == "__main__"):
    args = parseArgument()

    exit(main(args.inputFilePath, args.outputFilePath))
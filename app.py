# import Crypto  
# import Crypto.Random 
# from Crypto.PublicKey import RSA 
# from Crypto.Signature import PKCS1_v1_5  
# from Crypto.Hash import SHA 
import binascii 
import json  
# import requests 
from flask import Flask, jsonify, request 
from urllib.parse import urlparse 

app = Flask(__name__)

class Wallet:
    def __init__(self):
        random = Crypto.Random.new()
        self._private_key = RSA.generate(1024, random)
        self._public_key = self._private_key.public_key()

    @property
    def identity(self):
        pubkey = binascii.hexlify(self._public_key.exportKey(format='DER'))
        return pubkey.decode('ascii')   

# if __name__ == '__main__':
#   # myWallet = Wallet()
#   # blockchain = Blockchain()
#   app.run()

@app.route("/")
def hello():
    return "Hello World!"

if __name__ == '__main__':
    app.run()



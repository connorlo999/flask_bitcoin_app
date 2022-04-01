import Crypto  
import Crypto.Random 
from Crypto.PublicKey import RSA 
from Crypto.Signature import PKCS1_v1_5  
from Crypto.Hash import SHA 
from Crypto.Hash import SHA256
from datetime import datetime
import binascii 
import json  
import requests 
from flask import Flask, jsonify, request 
from urllib.parse import urlparse 


app = Flask(__name__)


class Transaction:

    def __init__(self, sender, recipient, value):
        self.sender = sender
        self.recipient = recipient
        self.value = value
        self.time = datetime.now()

    def to_dict(self):
        return {
            'sender': self.sender,
            'recipient': self.recipient,
            'value': self.value,
            'time': self.time
        }

    def add_signature(self, signature_):
        self.signature = signature_

    def verify_transaction_signature(self):
        if hasattr(self, 'signature'):
            public_key = RSA.importKey(binascii.unhexlify(self.sender))
            verifier = PKCS1_v1_5.new(public_key)
            h = SHA256.new(str(self.to_dict()).encode('utf8'))
            return verifier.verify(h, binascii.unhexlify(self.signature))
        else:
            return False

    def to_json(self):
        return json.dumps(self.__dict__, sort_keys=False)


class Wallet:
    
    def __init__(self):
        random = Crypto.Random.new().read
        self._private_key = RSA.generate(1024, random)
        self._public_key = self._private_key.publickey()

    def sign_transaction(self, transaction: Transaction):
        signer = PKCS1_v1_5.new(self._private_key)
        h = SHA256.new(str(transaction.to_dict()).encode('utf8'))
        return binascii.hexlify(signer.sign(h)).decode('ascii')

    @property
    def identity(self):
        pubkey = binascii.hexlify(self._public_key.exportKey(format='DER'))
        return pubkey.decode('ascii')

    
if __name__ == '__main__':
    myWallet = Wallet()
#   # blockchain = Blockchain()
    app.run()


@app.route("/")
def hello():
    return "Hello World!"



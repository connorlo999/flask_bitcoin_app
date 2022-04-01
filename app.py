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

# if __name__ == '__main__':
#   # myWallet = Wallet()
#   # blockchain = Blockchain()
#   app.run()

@app.route("/")
def hello():
    return "Hello World!"

if __name__ == '__main__':
    app.run()



import Crypto  
import Crypto.Random 
from Crypto.PublicKey import RSA 
from Crypto.Signature import PKCS1_v1_5  
from Crypto.Hash import SHA 
import binascii 
import json  
import requests 
from flask import Flask, jsonify, request, render_template
from urllib.parse import urlparse 


app = Flask(__name__)

@app.route("/")
def index():
    return render_template('index.html')

if __name__ == '__main__':
#   myWallet = Wallet()
#   blockchain = Blockchain()
  app.run(debug=True)


class Block:
  def __init__(self, index, transactions, timestamp, previous_hash):
    self.index = index
    self.transactions = transactions
    self.timestamp = timestamp
    self.previous_hash = previous_hash
    self.hash = None
    self.nonce = 0

  def to_dict(self):
    return({'index':self.index,
            'transactions':self.transactions,
            'timestamp':self.timestamp,
            'previous_hash':self.previous_hash,
            'nonce':self.nonce})
    
  def to_json(self):
    return json.dumps(self.__dict__)

  def compute_hash(self):
    return sha256(str(self.to_dict()).encode()).hexdigest()


class Transaction:
  def __init__(self, sender, recipient, value):
    self.sender = sender
    self.recipient = recipient
    self.value = value

  def to_dict(self):
    return({'sender': self.sender,'recipient':self.recipient,'value':self.value})

  def to_json(self):
    return json.dumps(self.__dict__)

  def add_signiture(self, signiture_):
    self.signiture = signiture_

  def verify_transaction_signiture(self):
    if hasattr(self,'signiture'):
      public_key = RSA.importKey(binascii.unhexlify(self.sender))
      verifier = PKCS1_v1_5.new(public_key)
      h = SHA256.new(str(self.to_dict()).encode('utf8'))
      return verifier.verify(h, binascii.unhexlify(self.signiture))
    else:
      return False


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

  @property
  def private(self):
      privatekey = binascii.hexlify(self._private_key.exportKey(format='DER'))
      return privatekey.decode('ascii')


class Blockchain:
  difficulty = 4

  def __init__(self):
    self.unconfirmed_transactions = []
    self.chain = []
    self.create_genesis_block()

  def create_genesis_block(self):
    genesis_block = Block(0, [], datetime.datetime.now().strftime("%m/%d/%y, %H:%M:%S"), "0")
    genesis_block.hash = genesis_block.compute_hash()
    self.chain.append(genesis_block.to_json())

  def add_new_transaction(self, transaction: Transaction):
    if transaction.verify_transaction_signiture():
      self.unconfirmed_transactions.append(transaction.to_json())
      return True
    else:
      return False

  def add_block(self, block, proof):

    previous_hash = self.last_block['hash']

    if previous_hash != block.previous_hash:
      return False

    if not self.is_valid_proof(block, proof):
      return False

    block.hash = proof
    self.chain.append(block.to_json())
    return True

  def is_valid_proof(self, block, block_hash):

    return (block_hash.startswith('0' * Blockchain.difficulty) and block_hash == block.compute_hash())

  def proof_of_work(self, block):
    block.nonce = 0
    computed_hash = block.compute_hash()
    while not computed_hash.startswith('0' * Blockchain.difficulty):
      block.nonce += 1
      computed_hash = block.compute_hash()
    return computed_hash

  def mine(self, myWallet):
    block_reward = Transaction("Block_Reward", myWallet.identity, "5.0").to_json()
    self.unconfirmed_transactions.insert(0, block_reward)
    if not self.unconfirmed_transactions:
      return False

    new_block = Block(index=self.last_block['index'] + 1, 
                      transactions=self.unconfirmed_transactions, 
                      timestamp=datetime.datetime.now().strftime("%m/%d/%y, %H:%M:%S"), 
                      previous_hash=self.last_block['hash'])
    
    proof = self.proof_of_work(new_block)
    if self.add_block(new_block, proof):
      self.unconfirmed_transactions = []
      return new_block
    else:
      return False

  @property
  def last_block(self):
    return json.loads(self.chain[-1])
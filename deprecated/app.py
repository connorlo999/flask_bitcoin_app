import Crypto
import Crypto.Random
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from hashlib import sha256
from Crypto.Hash import SHA256
from datetime import datetime
import binascii
import json
import requests
from flask import Flask, jsonify, request, render_template_string
from urllib.parse import urlparse
from json2html import *


app = Flask(__name__)


class json_format:
    def obj_to_json(self):
        return json.dumps(self, default=lambda o: o.__dict__)


class Transaction:
    def __init__(self, sender, recipient, value):
        self.sender = sender
        self.recipient = recipient
        self.value = value

    def to_dict(self):
        return {
            'sender': self.sender,
            'recipient': self.recipient,
            'value': self.value,
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
        return json.dumps(self.__dict__, sort_keys=False, default=str)


class Wallet:
    def __init__(self, deposit=0.0):
        random = Crypto.Random.new().read
        self._private_key = RSA.generate(1024, random)
        self._public_key = self._private_key.publickey()
        self._balance = deposit

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
        private_key = binascii.hexlify(self._private_key.exportKey(format='DER'))
        return private_key.decode('ascii')

    @property
    def balance(self):
        return self._balance

    def check_balance(self, transaction_cost):
        if self.balance >= transaction_cost:
            return True
        else:
            return False

    def deposit(self, deposit):
        self._balance += deposit

    def payment(self, cost):
        self._balance -= cost


class Blockchain:
    difficulty = 2
    nodes = set()

    def __init__(self):
        self.unconfirmed_transactions = []
        self.chain = []
        self.create_genesis_block()

    def create_genesis_block(self):
        genesis_block = Block(0, [], datetime.now().strftime("%m/%d/%y, %H:%M:%S"), "0")
        genesis_block.hash = genesis_block.compute_hash
        self.chain.append(genesis_block.to_json())

    def add_new_transaction(self, transaction: Transaction):
        if transaction.verify_transaction_signature():
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
        return block_hash.startswith('0' * Blockchain.difficulty) and block_hash == block.compute_hash

    def proof_of_work(self, block):
        block.nonce = 0
        computed_hash = block.compute_hash
        while not computed_hash.startswith('0' * Blockchain.difficulty):
            block.nonce += 1
            computed_hash = block.compute_hash
        return computed_hash

    def mine(self, myWallet):
        block_reward = Transaction("Block_Reward", myWallet.identity, "5.0").to_json()
        self.unconfirmed_transactions.insert(0, block_reward)
        myWallet.deposit(5.0)
        if not self.unconfirmed_transactions:
            return False

        new_block = Block(index=self.last_block['index'] + 1, transactions=self.unconfirmed_transactions,
                          timestamp=datetime.now().strftime("%m/%d/%y, %H:%M:%S"),
                          previous_hash=self.last_block['hash'])

        proof = self.proof_of_work(new_block)
        if self.add_block(new_block, proof):
            self.unconfirmed_transactions = []
            return new_block
        else:
            return False

    def register_node(self, node_url):

        parsed_url = urlparse(node_url)
        if parsed_url.netloc:
            self.nodes.add(parsed_url.netloc)
        elif parsed_url.path:
            self.nodes.add(parsed_url.path)
        else:
            raise ValueError('Invalid URL')

    def consensus(self):

        neighbours = self.nodes
        new_chain = None

        max_length = len(self.chain)

        for node in neighbours:
            response = requests.get('http://' + node + '/full_chain')

            if response.status_code == 200:
                length = response.json()['length']
                chain = response.json()['chain']

                if length > max_length and self.valid_chain(chain):
                    max_length = length
                    new_chain = chain

        if new_chain is not None:
            self.chain = json.loads(new_chain)
            return True

        return False

    def valid_chain(self, chain):

        current_index = 0
        chain = json.loads(chain)
        while current_index < len(chain):
            block = json.loads(chain[current_index])
            current_block = Block(block['index'],
                                  block['transactions'],
                                  block['timestamp'],
                                  block['previous_hash'],
                                  block['hash'],
                                  block['nonce'])
            if current_index + 1 < len(chain):
                if current_block.compute_hash() != json.loads(chain[current_index + 1])['previous_hash']:
                    return False
            if isinstance(current_block.transactions, list):
                for transaction in current_block.transactions:
                    transaction = json.loads(transaction)
                    if transaction['sender'] == 'Block_Reward':
                        continue
                    current_transaction = Transaction(transaction['sender'],
                                                      transaction['recipient'],
                                                      transaction['value'],
                                                      transaction['signature'])
                    if not current_transaction.verify_transaction_signature():
                        return False
                if not self.is_valid_proof(current_block, block['hash']):
                    return False
            current_index += 1
        return True

    @property
    def last_block(self):
        return json.loads(self.chain[-1])


class Block:
    def __init__(self, index, transactions, timestamp, previous_hash):
        self.index = index
        self.transactions = transactions
        self.timestamp = timestamp
        self.previous_hash = previous_hash
        self.hash = None
        self.nonce = 0

    def to_dict(self):
        return {
            'index': self.index,
            'transactions': self.transactions,
            'timestamp': self.timestamp,
            'previous_hash': self.previous_hash,
            'nonce': self.nonce
            }

    def to_json(self):
        return json.dumps(self.__dict__, default=str)

    @property
    def compute_hash(self):
        return sha256(str(self.to_dict()).encode()).hexdigest()


@app.route('/<wallet_identity>', methods=['GET'])
def wallet_identity(wallet_identity):

    pubkey = json.dumps(json_format.obj_to_json(globals()[f'{wallet_identity}'].identity))
    prikey = json.dumps(json_format.obj_to_json(globals()[f'{wallet_identity}'].private))
    balance = json.dumps(json_format.obj_to_json(globals()[f'{wallet_identity}'].balance))

    response = {
        'Public key': pubkey,
        'Private key': prikey,
        'Balance': balance
    }
    return jsonify(response), 200


@app.route('/new_transaction', methods=['POST'])
def new_transaction():

    values = request.get_json()

    required = ['recipient_address', 'amount']
    if not all(k in values for k in required):
        return 'Missing values', 400

    transaction_fee = values['amount'] + 0.5

    if myWallet.check_balance(transaction_fee):
        t = Transaction(myWallet.identity, values['recipient_address'], values['amount'])
        signature = myWallet.sign_transaction(t)
        t.add_signature(signature)
        myWallet.payment(0.5)
        transaction_result = blockchain.add_new_transaction(t)

        if transaction_result:
            myWallet.payment(values['amount'])
            response = {'message': 'Transaction will be added to the block'}
            return jsonify(response), 201
        else:
            response = {'message': 'Invalid Transaction!'}
            return jsonify(response), 406

    else:
        response = {'message': 'Please check your balance!',
                    'Reminder': '0.5 is for transaction fee'}
        return jsonify(response), 406


@app.route('/get_transactions', methods=['GET'])
def get_transactions():
    transactions = blockchain.unconfirmed_transactions
    response = {'transactions': transactions}
    return jsonify(response), 200


@app.route('/chain', methods=['GET'])
def last_ten_blocks():

    response = {
        'chain': blockchain.chain[-10:],
        'length': len(blockchain.chain)
    }
    return jsonify(response), 200


@app.route('/full_chain', methods=['GET'])
def full_chain():

    response = {
        'chain': json.dumps(blockchain.chain),
        'length': len(blockchain.chain),
    }
    #return jsonify(response), 200

    # temporary measure for visualization, see if there is any better way
    html_data = ''
    for item in blockchain.chain:
        html_data += json2html.convert(json=item)
        html_data += '<br><br>'
    return render_template_string(html_data)


@app.route('/get_nodes', methods=['GET'])
def get_nodes():

    nodes = list(blockchain.nodes)
    response = {'nodes': nodes}
    return jsonify(response), 200


@app.route('/register_node', methods=['POST'])
def register_node():

    values = request.get_json()

    required = ['node', 'com_port']
    if not all(k in values for k in required):
        return 'Missing values', 400

    if (values['node'] == "" and values['com_port'] == "") or values['node'] == "":
        return 'Input invalid', 400

    node = values['node']
    if values['com_port'] != "":
        com_port = values['com_port']
        blockchain.register_node(request.remote_addr + ":" + com_port)

    blockchain.register_node(node)
    node_list = requests.get('http://' + node + '/get_nodes')
    if node_list.status_code == 200:
        node_list = node_list.json()['nodes']
        for node in node_list:
            blockchain.register_node(node)
    for new_nodes in blockchain.nodes:
        requests.post('http://' + new_nodes + '/register_node',
                      data={'com_port': str(port)})

    replaced = blockchain.consensus()

    if replaced:
        response = {
            'message': 'Longer authoritative chain found from peers, replacing ours',
            'total_nodes': [node for node in blockchain.nodes],
            'blockchain': blockchain.chain
        }
    else:
        response = {
            'message': 'New nodes have been added, but our chain is authoritative',
            'total_nodes': [node for node in blockchain.nodes],
            'blockchain': blockchain.chain
        }
    return jsonify(response), 201


@app.route('/consensus', methods=['GET'])
def consensus():
    replaced = blockchain.consensus()
    if replaced:
        response = {
            'message': 'Our chain was replaced',
        }
    else:
        response = {
            'message': 'Our chain is authoritative',
        }
    return jsonify(response), 200


@app.route('/mine', methods=['GET'])
def mine():
    new_block = blockchain.mine(myWallet)
    for node in blockchain.nodes:
        requests.get('http://' + node + '/consensus')
    response = {
        'index': new_block.index,
        'transactions': new_block.transactions,
        'timestamp': new_block.timestamp,
        'nonce': new_block.nonce,
        'hash': new_block.hash,
        'previous_hash': new_block.previous_hash
    }
    return jsonify(response), 200


if __name__ == '__main__':
    myWallet = Wallet()    # create wallet with $0
    Wallet_2 = Wallet(300.0)  # e.g. create wallet with $300
    Wallet_3 = Wallet(200.0)
    blockchain = Blockchain()
    port = 5000
    app.run(host='127.0.0.1', port=port, debug=True)


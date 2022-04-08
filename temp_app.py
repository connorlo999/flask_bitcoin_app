import Crypto
import Crypto.Random
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from hashlib import sha256
from Crypto.Hash import SHA256
from datetime import datetime
from json import JSONEncoder
import binascii
import json
import requests
from flask import Flask, jsonify, request, render_template_string
from urllib.parse import urlparse
# from json2html import *


# import time
# import atexit
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.executors.pool import ThreadPoolExecutor, ProcessPoolExecutor
import random

app = Flask(__name__)


class json_format(JSONEncoder):
    def obj_to_json(self):
        return self


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


class Block:
    def __init__(self, index, transactions, timestamp, previous_hash, hash_=0, nonce=0, difficulty=2):
        self.index = index
        self.transactions = transactions
        self.timestamp = timestamp
        self.previous_hash = previous_hash
        self.hash = hash_
        self.nonce = nonce
        self.difficulty = difficulty

    def to_dict(self):
        return {
            'index': self.index,
            'transactions': self.transactions,
            'timestamp': self.timestamp,
            'previous_hash': self.previous_hash,
            'nonce': self.nonce,
            'difficulty': self.difficulty
            }

    def to_json(self):
        return json.dumps(self.__dict__, default=str)

    @property
    def compute_hash(self):
        return sha256(str(self.to_dict()).encode()).hexdigest()


class Blockchain:

    min_diff = 2
    max_diff = 5

    def __init__(self):
        self.unconfirmed_transactions = []
        self.chain = []
        self.create_genesis_block()
        self.nodes = set()

    def difficulty(self, last_block, last_block_2):
        difficulty = last_block['difficulty']

        if len(self.chain) > 2:

            last_block1_timestamp = last_block['timestamp']
            last_block2_timestamp = last_block_2['timestamp']

            struct_time_1 = datetime.strptime(last_block1_timestamp, "%m/%d/%y, %H:%M:%S")
            struct_time_2 = datetime.strptime(last_block2_timestamp, "%m/%d/%y, %H:%M:%S")

            time_diff = struct_time_1 - struct_time_2

            if time_diff.total_seconds() > 30 and difficulty > self.min_diff:
                difficulty -= 1
            if time_diff.total_seconds() < 10 and difficulty < self.max_diff:
                difficulty += 1

        return difficulty

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
        return block_hash.startswith('0' * block.difficulty) and block_hash == block.compute_hash

    def proof_of_work(self, block):
        block.nonce = 0
        computed_hash = block.compute_hash
        while not computed_hash.startswith('0' * block.difficulty):
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
        new_block.difficulty = self.difficulty(self.last_block, self.last_block_2)
        proof = self.proof_of_work(new_block)
        if self.add_block(new_block, proof):
            self.unconfirmed_transactions = []
            return new_block
        else:
            return False

    def interest(self, wallet_identity):
        if wallet_identity.balance == 0:
            return False
        rate = 5
        interest_earn = round(wallet_identity.balance*(1+rate/100-1),2)

        interest_trans = Transaction("Interest", wallet_identity.identity, str(interest_earn)).to_json()
        self.unconfirmed_transactions.insert(0, interest_trans)
        wallet_identity.deposit(interest_earn)
        if not self.unconfirmed_transactions:
            return False

        new_block = Block(index=self.last_block['index'] + 1, transactions=self.unconfirmed_transactions,
                          timestamp=datetime.now().strftime("%m/%d/%y, %H:%M:%S"),
                          previous_hash=self.last_block['hash'])
        new_block.difficulty = self.difficulty(self.last_block, self.last_block_2)
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

        if new_chain:
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
                                  block['nonce'],
                                  block['difficulty'])
            current_block_hash = str(current_block.hash)
            if hasattr(current_block, 'hash'):
                delattr(current_block, 'hash')
            if current_index + 1 < len(chain):
                if current_block.compute_hash != json.loads(chain[current_index + 1])['previous_hash']:
                    return False
            if isinstance(current_block.transactions, list):
                for transaction in current_block.transactions:
                    transaction = json.loads(transaction)
                    if transaction['sender'] == 'Block_Reward':
                        continue
                    current_transaction = Transaction(transaction['sender'],
                                                      transaction['recipient'],
                                                      transaction['value'])
                    if hasattr(current_transaction, 'signature'):
                        current_transaction.signature = transaction['signature']
                        if not current_transaction.verify_transaction_signature():
                            return False
                    hasattr(current_block, 'hash')
                    if not self.is_valid_proof(current_block, current_block_hash):
                        return False
            current_index += 1
        return True

    @property
    def last_block(self):
        return json.loads(self.chain[-1])

    @property
    def last_block_2(self):
        if len(self.chain) > 2:
            return json.loads(self.chain[-2])


@app.route('/<wallet_identity>', methods=['GET'])
def wallet_identity(wallet_identity):

    pub_key = json.dumps(globals()[f'{wallet_identity}'].identity, cls=json_format)
    pri_key = json.dumps(globals()[f'{wallet_identity}'].private, cls=json_format)
    balance = json.dumps(globals()[f'{wallet_identity}'].balance, cls=json_format)

    response = {
        'Public key': pub_key,
        'Private key': pri_key,
        'Balance': balance
    }
    return jsonify(response), 200


@app.route('/new_transaction', methods=['POST'])
def new_transaction():
    values = request.get_json()

    required = ['recipient_address', 'amount']
    if not all(k in values for k in required):
        return 'Missing values', 400

    signature = values['signature']

    if signature == "":
        t = Transaction(myWallet.identity, values['recipient_address'], values['amount'])
        signature = myWallet.sign_transaction(t)
        response = {'message': 'Please include this signature in your transaction.',
                    'signature': signature}
        return jsonify(response), 201

    transaction_fee = values['amount'] + 0.5

    if myWallet.check_balance(transaction_fee):
        t = Transaction(myWallet.identity, values['recipient_address'], values['amount'])
        t.add_signature(signature)
        transaction_result = blockchain.add_new_transaction(t)

        if transaction_result:
            myWallet.payment(transaction_fee)
            response = {'message': 'Transaction will be added to the block'}
            return jsonify(response), 201
        else:
            myWallet.payment(0.5)
            response = {'message': 'Invalid Transaction! There is a cost of the network gas fee.'}
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
    return jsonify(response), 200

    # temporary measure for visualization, see if there is any better way
    # html_data = ''
    #for item in blockchain.chain:
    #    html_data += json2html.convert(json=item)
    #    html_data += '<br><br>'
    # return render_template_string(html_data)


@app.route('/get_nodes', methods=['GET'])
def get_nodes():

    nodes = list(blockchain.nodes)
    response = {'nodes': nodes}
    return jsonify(response), 200


@app.route('/register_node', methods=['POST'])
def register_node():

    values = request.json

    required = ['node', 'com_port']

    if (values['node'] == "" and values['com_port'] == "") or values['node'] == "" or values['com_port'] == str(port):
        return 'Input invalid', 400

    new_address = f'{values["node"]}:{values["com_port"]}'
    if new_address in blockchain.nodes:
        return 'Node Added', 200

    r = requests.get(f'http://{new_address}/get_nodes')

    if r.status_code != 200:
        response = {
            'message': 'Something went wrong',
        }
        return jsonify(response), 400

    else:
        node_list = r.json()["nodes"]
        blockchain.register_node(f'http://{new_address}')
        data = {"node": str(host), "com_port": str(port)}
        headers = {'Content-type': 'application/json', 'Accept': 'text/plain'}
        requests.post(f'http://{new_address}/register_node', data=json.dumps(data), headers=headers)

        for node in node_list:
            if not(node in blockchain.nodes) and node != f'127.0.0.1:{port}':
                data = {"node": str(host), "com_port": str(port)}
                headers = {'Content-type': 'application/json', 'Accept': 'text/plain'}
                requests.post(f'http://{node}/register_node', data=json.dumps(data), headers=headers)

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
        'previous_hash': new_block.previous_hash,
        'hash': new_block.hash,
        'nonce': new_block.nonce,
        'difficulty': new_block.difficulty
    }
    return jsonify(response), 200

@app.route('/interest', methods=['POST'])
def interest():
    values = request.json
    wallet_identity = values['wallet_identity']
    new_block = blockchain.interest(globals()[f'{wallet_identity}'])
    for node in blockchain.nodes:
        requests.get('http://' + node + '/consensus')
    if new_block:
        response = {
            'index': new_block.index,
            'transactions': new_block.transactions,
            'timestamp': new_block.timestamp,
            'previous_hash': new_block.previous_hash,
            'hash': new_block.hash,
            'nonce': new_block.nonce,
            'difficulty': new_block.difficulty
        }
        return jsonify(response), 200
    else:
        response = {
            'message': 'No interest!'
        }
        return jsonify(response), 200


executors = {
    'default': ThreadPoolExecutor(16),
    'processpool': ProcessPoolExecutor(4)
}


def auto_interest_exc():
    headers = {'Content-type': 'application/json', 'Accept': 'text/plain'}
    data = {"wallet_identity": "interest_wallet"}
    requests.post(f'http://{host}:{port}/interest', data=json.dumps(data), headers=headers)


sched = BackgroundScheduler(daemon=True, job_defaults={'max_instances': 2})
sched.add_job(auto_interest_exc, 'interval', seconds=random.randint(28, 32))

if __name__ == '__main__':
    myWallet = Wallet()    # create wallet with $0
    interest_wallet = Wallet(300.0)  # e.g. create wallet with $300
    Wallet_3 = Wallet(200.0)
    blockchain = Blockchain()
    port = 5000
    host = '127.0.0.1'
    sched.start()
    app.run(host=host, port=port, debug=True, use_reloader=False)

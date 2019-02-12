'''This blockchain class is responsible for managing the chain. It will store transactions
and have some helper methods for adding new blocks to chain
Each block has an index, a timestamp, a list of transactions,
a proof and hash of previous block.
'''

import hashlib
import json
from textwrap import dedent
from time import time
from uuid import uuid4

from flask import Flask, jsonify, request

import socket
from threading import Thread
import pickle
from flask import Flask, request, render_template, url_for








'''
class Block:
    blockNo = 0
    data = None
    next = None
    hash = None
    nonce = 0
    previous_hash = 0x0
    timestamp = datetime.datetime.now()

    def __init__(self, data):
        self.data = data

    def hash(self):
        h = hashlib.sha256()
        h.update(
        str(self.nonce).encode('utf-8') +
        str(self.data).encode('utf-8') +
        str(self.previous_hash).encode('utf-8') +
        str(self.timestamp).encode('utf-8') +
        str(self.blockNo).encode('utf-8')
        )
        return h.hexdigest()

    def __str__(self):
        return "Block Hash: " + str(self.hash()) + "\nBlockNo: " + str(self.blockNo) + "\nBlock Data: " + str(self.data) + "\nHashes: " + str(self.nonce) + "\n--------------"

class Blockchain:

    diff = 20
    maxNonce = 2**32
    target = 2 ** (256-diff)

    block = Block("Genesis")
    dummy = head = block

    def add(self, block):

        block.previous_hash = self.block.hash()
        block.blockNo = self.block.blockNo + 1

        self.block.next = block
        self.block = self.block.next

    def mine(self, block):
        for n in range(self.maxNonce):
            if int(block.hash(), 16) <= self.target:
                self.add(block)
                print(block)
                break
            else:
                block.nonce += 1

blockchain = Blockchain()

for n in range(10):
    blockchain.mine(Block("Block " + str(n+1)))

while blockchain.head != None:
    print(blockchain.head)
    blockchain.head = blockchain.head.next'''

'''
class Block:
    def __init__(self,index,timestamp,data,previous_hash=''):
        self.index = index
        self.timestamp = timestamp
        self.data = data
        self.previous_hash = previous_hash
        self.hash = self.calclateHash()

    def calclateHash(self):
        h = hashlib.sha256()
        h.update(
        str(self.index).encode('utf-8') +
        json.dumps(self.data).encode('utf-8') +
        str(self.previous_hash).encode('utf-8') +
        str(self.timestamp).encode('utf-8')
        )
        return h.hexdigest()


class Blockchain:
    def __init__(self):
        self.chain = [self.create_genesis_block()]
        self.current_transactions = []

    def create_genesis_block(self):
        return Block(0,"01/01/2017","Genesis Block","0")

    def getLatestBlock(self):
        return self.chain[len(self.chain)-1]

    def new_block(self,newBlock):
        newBlock.previous_hash = self.getLatestBlock().hash
        newBlock.hash = newBlock.calclateHash()
        self.chain.append(newBlock)

    def printchain(self):

        return self.chain[0]

prasun = Blockchain()
prasun.new_block(Block(1,"10/10/2018",{'amount':4}))
print(json.dumps(prasun))
'''
'''After new_transaction() adds a transaction to the list,
  it returns the index of the block which the transaction
  will be added to—the next one to be mined.
 T'''

import hashlib
import json
from time import time
from urllib.parse import urlparse
from uuid import uuid4

from flask import Flask, jsonify, request
from Crypto.PublicKey import RSA
from Crypto import Random
from Crypto.Hash import SHA256


random_generator = Random.new().read
GerbersPrivateKey = RSA.generate(1024, random_generator)
GerbersPublicKey = GerbersPrivateKey.publickey()
random_generator = Random.new().read
HappyFamilyPrivateKey = RSA.generate(1024, random_generator)
HappyFamilyPublicKey = HappyFamilyPrivateKey.publickey()
random_generator = Random.new().read
NestlePrivateKey = RSA.generate(1024, random_generator)
NestlePublicKey = NestlePrivateKey.publickey()
random_generator = Random.new().read
AmazonPrivateKey = RSA.generate(1024, random_generator)
AmazonPublicKey = AmazonPrivateKey.publickey()
random_generator = Random.new().read
EbayPrivateKey = RSA.generate(1024, random_generator)
EbayPublicKey = EbayPrivateKey.publickey()
random_generator = Random.new().read
AlibabaPrivateKey = RSA.generate(1024, random_generator)
AlibabaPublicKey = AlibabaPrivateKey.publickey()







class Blockchain:
    manufacture_list={
    'Gerbers':{'Cereals':100,'Purey':100, 'Oats':100,
                'prkey': GerbersPrivateKey,
                'pukey': GerbersPublicKey
                },
    'HappyFamily':{'Cereals':100,'Purey':100, 'Oats':100,
                    'prkey': HappyFamilyPrivateKey,
                    'pukey': HappyFamilyPublicKey
                },
    'Nestle': {'Cereals':100,'Purey':100, 'Oats':100,
               'prkey': NestlePrivateKey,
               'pukey': NestlePublicKey

               }
    }
    print("Checking the value",AmazonPublicKey==EbayPublicKey)
    seller_list = {
    'Amazon':{
        'Gerber':{'Cereals':0,'Purey':0, 'Oats':0},
        'Nestle':{'Cereals':0,'Purey':0, 'Oats':0},
        'HappyFamily':{'Cereals':0,'Purey':0, 'Oats':0},
        'prkey': AmazonPrivateKey,
        'pukey': AmazonPublicKey
        },
    'eBay':{
        'Gerber':{'Cereals':0,'Purey':0, 'Oats':0},
        'Nestle':{'Cereals':0,'Purey':0, 'Oats':0},
        'HappyFamily':{'Cereals':0,'Purey':0, 'Oats':0},
        'prkey': EbayPrivateKey,
        'pukey': EbayPublicKey
    },
    'Alibaba':{
        'Gerber':{'Cereals':0,'Purey':0, 'Oats':0},
        'Nestle':{'Cereals':0,'Purey':0, 'Oats':0},
        'HappyFamily':{'Cereals':0,'Purey':0, 'Oats':0},
        'prkey': AlibabaPrivateKey,
        'pukey': AlibabaPublicKey
    }
    }

    retailer_list=[]

    def __init__(self):
        self.current_transactions = []
        self.chain = []
        self.nodes = set()

        # Create the genesis block
        self.new_block(previous_hash='1', proof=100)


        self.soc = socket.socket(type=socket.SOCK_DGRAM)
        self.hostname = socket.gethostname()
        self.port = 9000

        # bind the address to the socket created
        self.soc.bind((self.hostname, self.port))

        # set the ports of the nodes connected to it as susceptible nodes
        self.node_list = [9001]

        # call the threads to begin the magic
        self.start_threads()

    def receive_message(self):
        while(True):
            message, address = self.soc.recvfrom(4000)
            self.chain = pickle.loads(message)

    def send_chain(self):
        message_to_send = pickle.dumps(self.chain)

        for p in self.node_list:
            self.soc.sendto(message_to_send, (self.hostname, p))

    def start_threads(self):
        # two threads for entering and getting a message.
        # it will enable each node to be able to
        # enter a message and still be able to receive a message
        Thread(target=self.receive_message).start()




    def register_node(self, address):
        """
        Add a new node to the list of nodes
        :param address: Address of node. Eg. 'http://192.168.0.5:5000'
        """

        parsed_url = urlparse(address)
        if parsed_url.netloc:
            self.nodes.add(parsed_url.netloc)
        elif parsed_url.path:
            # Accepts an URL without scheme like '192.168.0.5:5000'.
            self.nodes.add(parsed_url.path)
        else:
            raise ValueError('Invalid URL')


    def valid_chain(self, chain):
        """
        Determine if a given blockchain is valid
        :param chain: A blockchain
        :return: True if valid, False if not
        """

        last_block = chain[0]
        current_index = 1

        while current_index < len(chain):
            block = chain[current_index]
            print(f'{last_block}')
            print(f'{block}')
            print("\n-----------\n")
            # Check that the hash of the block is correct
            if block['previous_hash'] != self.hash(last_block):
                return False

            # Check that the Proof of Work is correct
            if not self.valid_proof(last_block['proof'], block['proof'], last_block['previous_hash']):
                return False

            last_block = block
            current_index += 1

        return True

    def resolve_conflicts(self):
        """
        This is our consensus algorithm, it resolves conflicts
        by replacing our chain with the longest one in the network.
        :return: True if our chain was replaced, False if not
        """

        neighbours = self.nodes
        new_chain = None

        # We're only looking for chains longer than ours
        max_length = len(self.chain)

        # Grab and verify the chains from all the nodes in our network
        for node in neighbours:
            response = request.get_json(f'http://{node}/chain')

            if response.status_code == 200:
                length = response.json()['length']
                chain = response.json()['chain']

                # Check if the length is longer and the chain is valid
                if length > max_length and self.valid_chain(chain):
                    max_length = length
                    new_chain = chain

        # Replace our chain if we discovered a new, valid chain longer than ours
        if new_chain:
            self.chain = new_chain
            return True

        return False

    def new_block(self, proof, previous_hash):
        """
        Create a new Block in the Blockchain
        :param proof: The proof given by the Proof of Work algorithm
        :param previous_hash: Hash of previous Block
        :return: New Block
        """

        block = {
            'index': len(self.chain) + 1,
            'timestamp': time(),
            'transactions': self.current_transactions,
            'proof': proof,
            'previous_hash': previous_hash or self.hash(self.chain[-1]),
        }

        # Reset the current list of transactions
        self.current_transactions = []

        self.chain.append(block)
        return block

    def new_transaction(self, manufacturer,seller,product_name,quantity):
        """
        Creates a new transaction to go into the next mined Block
        :param sender: Address of the Sender
        :param recipient: Address of the Recipient
        :param amount: Amount
        :return: The index of the Block that will hold this transaction
        """
        # if manufacture_list contains manufacturer and seller_list contains seller and quantity <
        # the value present in dictionary value.
        # Then only the block will be added to chain
        # manufacturer = set(manufacturer)

        message = product_name
        hash = SHA256.new(message.encode('utf-8')).digest()
        signature = self.manufacture_list[manufacturer]['prkey'].sign(hash, '')

        seller_value=False
        if seller in self.seller_list:
            print('Inside check loop 2 seller')
            seller_value=True

        if(self.manufacture_list[manufacturer]['pukey'].verify(hash, signature)):
            if(manufacturer in self.manufacture_list):
                if (quantity < self.manufacture_list[manufacturer][product_name]) and (seller_value):
                    self.manufacture_list[manufacturer][product_name]=self.manufacture_list[manufacturer][product_name]-quantity
                    self.seller_list[seller][manufacturer][product_name]=self.seller_list[seller][manufacturer][product_name]+quantity
                    cereal_value=self.seller_list[seller][manufacturer]['Cereals']
                    purey_value=self.seller_list[seller][manufacturer]['Purey']
                    oats_value= self.seller_list[seller][manufacturer]['Oats']
                    self.current_transactions.append({
                            'manufacturer': manufacturer,
                            'seller_public':self.seller_list[seller]['pukey'].exportKey('DER').hex(),
                            'seller_list': {
                                "Cereals":cereal_value ,
                                "Oats": oats_value,
                                "Purey": purey_value
                            },
                            'product_name': product_name,
                            'quantity': quantity
                    })
                    print('Value Appended')
                    print(self.manufacture_list[manufacturer])
                    print(self.seller_list[seller]['pukey'].exportKey('DER').hex())
                    return self.last_block['index'] + 1
                else:
                    return 9
        else:
            return 5


    def new_transaction_seller(self, manufacturer,sellerA,sellerB,product_name,quantity,seller_publicKey):
        """
        Creates a new transaction to go into the next mined Block
        :param sender: Address of the Sender
        :param recipient: Address of the Recipient
        :param amount: Amount
        :return: The index of the Block that will hold this transaction
        """
        manufacturer_value=False
        if manufacturer in self.seller_list[sellerA]:
            print('Inside  seller transaction')
            manufacturer_value=True

        message = product_name
        hash = SHA256.new(message.encode('utf-8')).digest()
        signature = self.seller_list[sellerA]['prkey'].sign(hash, '')

        if(RSA.importKey(bytes.fromhex(seller_publicKey)).verify(hash, signature)) and self.seller_list[sellerA]['pukey']== RSA.importKey(bytes.fromhex(seller_publicKey)) :
            if(sellerA in self.seller_list):
                if (quantity < self.seller_list[sellerA][manufacturer][product_name]):
                    self.seller_list[sellerA][manufacturer][product_name]=self.seller_list[sellerA][manufacturer][product_name]-quantity
                    self.seller_list[sellerB][manufacturer][product_name]=self.seller_list[sellerB][manufacturer][product_name]+quantity

                    cereal_value=self.seller_list[sellerB][manufacturer]['Cereals']
                    purey_value=self.seller_list[sellerB][manufacturer]['Purey']
                    oats_value= self.seller_list[sellerB][manufacturer]['Oats']
                    print("Checking the values of seller a And B",seller_publicKey== self.seller_list[sellerB]['pukey'].exportKey('DER').hex())
                    self.current_transactions.append({
                            'manufacturer': manufacturer,
                            'sellerA':sellerA,
                            'seller_name':sellerB,
                            'seller_public':self.seller_list[sellerB]['pukey'].exportKey('DER').hex(),
                            'seller_list': {
                                "Cereals":cereal_value ,
                                "Oats": oats_value,
                                "Purey": purey_value
                            },
                            'product_name': product_name,
                            'quantity': quantity
                    })
                    print('Value Appended in new seller block')
                    print(self.seller_list[sellerA])
                    return self.last_block['index'] + 1
                else:
                    return 9
        else:
            return 8


    @property
    def last_block(self):
        return self.chain[-1]

    @staticmethod
    def hash(block):
        """
        Creates a SHA-256 hash of a Block
        :param block: Block
        """

        # We must make sure that the Dictionary is Ordered, or we'll have inconsistent hashes
        block_string = json.dumps(block, sort_keys=True).encode()
        return hashlib.sha256(block_string).hexdigest()

    def proof_of_work(self, last_block):
        """
        Simple Proof of Work Algorithm:
         - Find a number p' such that hash(pp') contains leading 4 zeroes
         - Where p is the previous proof, and p' is the new proof
        :param last_block: <dict> last Block
        :return: <int>
        """

        last_proof = last_block['proof']
        last_hash = self.hash(last_block)

        proof = 0
        while self.valid_proof(last_proof, proof, last_hash) is False:
            proof += 1

        return proof

    @staticmethod
    def valid_proof(last_proof, proof, last_hash):
        """
        Validates the Proof
        :param last_proof: <int> Previous Proof
        :param proof: <int> Current Proof
        :param last_hash: <str> The hash of the Previous Block
        :return: <bool> True if correct, False if not.
        """

        guess = f'{last_proof}{proof}{last_hash}'.encode()
        guess_hash = hashlib.sha256(guess).hexdigest()
        return guess_hash[:4] == "0000"


# Instantiate the Node
app = Flask(__name__)
# Generate a globally unique address for this node
node_identifier = str(uuid4()).replace('-', '')
# Instantiate the Blockchain
blockchain = Blockchain()

@app.route('/')
def home():
	return render_template('home.html')

@app.route('/mine', methods=['GET'])
def mine():
    # We run the proof of work algorithm to get the next proof...
    last_block = blockchain.last_block
    proof = blockchain.proof_of_work(last_block)

    # We must receive a reward for finding the proof.
    # The sender is "0" to signify that this node has mined a new coin.

    # Forge the new Block by adding it to the chain
    previous_hash = blockchain.hash(last_block)
    block = blockchain.new_block(proof, previous_hash)

    index= block['index']
    transactions= block['transactions']
    print(transactions)
    proof = block['proof']
    previous_hash=block['previous_hash']

    return render_template("mine.html", index =index, transactions=transactions, proof=proof, previous_hash=previous_hash)

# Add to manufacturer list
@app.route('/transactions', methods=['POST'])
def new_transaction():
    print("transaction Begin")
    # values = request.json
    # print(format(values))


    if request.method == 'POST':
        manufacturer=request.form['sender']
        seller=request.form['receiver']
        product_name=request.form['product']
        quantity=request.form['quantity']

    print(manufacturer)
    values=[manufacturer, seller, product_name,quantity]
    print(values[0])

    #Check that the required fields are in the POST'ed data
    # required = ['manufacturer', 'seller', 'product_name','quantity']
    # for k in values:
    #     print(k)
    # if not all(k in values for k in required):
    #     return 'Missing values', 400

    # Create a new Transaction
    index = blockchain.new_transaction(manufacturer, seller, product_name, int(quantity))

    response = 'Transaction will be added to Block', index
    return render_template("home.html" , response=response)

# Add to Retailer list
@app.route('/transactions/new/seller', methods=['POST'])
def new_transaction_seller():
    print("transaction Begin Seller")
    # values = request.json
    # print(format(values))
    #Check that the required fields are in the POST'ed data
    if request.method == 'POST':
        manufacturer=request.form['sender']
        sellerA=request.form['receiver']
        sellerB=request.form['reciever']
        product_name=request.form['product']
        quantity=request.form['quantity']
    required = ['manufacturer', 'sellerA','sellerB', 'product_name','quantity', 'seller_publicKey']
    for l in values:
        print(l)
    if not all(l in values for l in required):
        return 'Missing values', 400


    # Create a new Transaction
    # index = blockchain.new_transaction_seller(values['manufacturer'],
            # values['sellerA'],values['sellerB'] ,values['product_name'], values['quantity'],values['seller_publicKey'])

    # response = {'message': f'Transaction will be added to Block {index}'}
    return jsonify("Hello")

@app.route('/chain', methods=['GET'])
def full_chain():
    chain= blockchain.chain
    length= len(blockchain.chain)
    blockchain.send_chain()
    return render_template("chain.html", chain=chain, length=length)


@app.route('/nodes/register', methods=['POST'])
def register_nodes():
    values = request.get_json()

    nodes = values.get('nodes')
    if nodes is None:
        return "Error: Please supply a valid list of nodes", 400

    for node in nodes:
        blockchain.register_node(node)

    response = {
        'message': 'New nodes have been added',
        'total_nodes': list(blockchain.nodes),
    }
    return jsonify(response), 201


@app.route('/nodes/resolve', methods=['GET'])
def consensus():
    replaced = blockchain.resolve_conflicts()

    if replaced:
        response = {
            'message': 'Our chain was replaced',
            'new_chain': blockchain.chain
        }
    else:
        response = {
            'message': 'Our chain is authoritative',
            'chain': blockchain.chain
        }

    return jsonify(response), 200


if __name__ == '__main__':
    from argparse import ArgumentParser

    parser = ArgumentParser()
    parser.add_argument('-p', '--port', default=9000, type=int, help='port to listen on')
    args = parser.parse_args()
    port = args.port

    app.run(host='0.0.0.0', port=port)


    # {
    #     "manufacturer": "HappyFamily",
    #     "seller": "Amazon",
    #     "product_name": "Cereals",
    #     "quantity": 10
    # }
#     {
#         {
# 	"manufacturer": "HappyFamily",
# 	"sellerA": "Amazon",
# 	"sellerB":"eBay",
# 	"product_name": "Cereals",
# 	"seller_publicKey":"30819f300d06092a864886f70d010101050003818d0030818902818100b46d6208331dd37c32f7e1efe324850502e0a012f6aece5053a84059d3b9a732abd6a50deeb3a6555062066e9cd1e23cf308ba290c09d9efe7d5b5cddc0d14c9d5621b0f1cdfc87b0080ee470a5eddaefbe6396304274349b2cb75c76e2071a3694b162c113e855a5f2f89b48f5cd77fc9b5a38cb2a50eb8cb4f9414239eb9b30203010001",
# 	"quantity": 5
# }
#     }

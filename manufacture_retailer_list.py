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


class Reatailer_Manufacturer_List:
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
    
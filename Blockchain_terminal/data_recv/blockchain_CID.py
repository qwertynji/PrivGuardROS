import pika
import random
import time
import web3
from web3 import Web3
import time
import requests
from socket import *
import redis

# RabbitMQ 服务器和端口配置
rabbitmq_host = '8.138.56.15'
rabbitmq_port = 5672
connection_parameters = pika.ConnectionParameters(host=rabbitmq_host, port=rabbitmq_port)
w3 = Web3(Web3.HTTPProvider('http://localhost:8545')) # 设置Ethereum节点地址
contract_address = '0x4bb741A28933b047a2a06E2cDC66E5cc64c07948'
contract_abi = [{"constant":True,"inputs":[{"internalType":"uint256","name":"","type":"uint256"}],"name":"fileIdToCid","outputs":[{"internalType":"string","name":"","type":"string"}],"payable":False,"stateMutability":"view","type":"function"},{"constant":True,"inputs":[{"internalType":"uint256","name":"","type":"uint256"}],"name":"fileIdToHash","outputs":[{"internalType":"string","name":"","type":"string"}],"payable":False,"stateMutability":"view","type":"function"},{"constant":True,"inputs":[{"internalType":"uint256","name":"fileId","type":"uint256"}],"name":"getFileCid","outputs":[{"internalType":"string","name":"","type":"string"}],"payable":False,"stateMutability":"view","type":"function"},{"constant":True,"inputs":[{"internalType":"uint256","name":"fileId","type":"uint256"}],"name":"getFileHash","outputs":[{"internalType":"string","name":"","type":"string"}],"payable":False,"stateMutability":"view","type":"function"},{"constant":True,"inputs":[{"internalType":"uint256","name":"userId","type":"uint256"}],"name":"getUserAccess","outputs":[{"internalType":"string","name":"","type":"string"}],"payable":False,"stateMutability":"view","type":"function"},{"constant":True,"inputs":[{"internalType":"uint256","name":"userId","type":"uint256"}],"name":"getUserSignature","outputs":[{"internalType":"string","name":"","type":"string"}],"payable":False,"stateMutability":"view","type":"function"},{"constant":False,"inputs":[{"internalType":"uint256","name":"fileId","type":"uint256"},{"internalType":"string","name":"cid","type":"string"}],"name":"storeFileIdToCid","outputs":[],"payable":False,"stateMutability":"nonpayable","type":"function"},{"constant":False,"inputs":[{"internalType":"uint256","name":"fileId","type":"uint256"},{"internalType":"string","name":"hash","type":"string"}],"name":"storeFileIdToHash","outputs":[],"payable":False,"stateMutability":"nonpayable","type":"function"},{"constant":False,"inputs":[{"internalType":"uint256","name":"userId","type":"uint256"},{"internalType":"string","name":"access","type":"string"}],"name":"storeUserIdToAccess","outputs":[],"payable":False,"stateMutability":"nonpayable","type":"function"},{"constant":False,"inputs":[{"internalType":"uint256","name":"userId","type":"uint256"},{"internalType":"string","name":"signature","type":"string"}],"name":"storeUserIdToSignature","outputs":[],"payable":False,"stateMutability":"nonpayable","type":"function"},{"constant":True,"inputs":[{"internalType":"uint256","name":"","type":"uint256"}],"name":"userIdToAccess","outputs":[{"internalType":"string","name":"","type":"string"}],"payable":False,"stateMutability":"view","type":"function"},{"constant":True,"inputs":[{"internalType":"uint256","name":"","type":"uint256"}],"name":"userIdToSignature","outputs":[{"internalType":"string","name":"","type":"string"}],"payable":False,"stateMutability":"view","type":"function"}]
contract = w3.eth.contract(address=contract_address, abi=contract_abi)
from_account = w3.eth.accounts[0]
passwd = '123'  
w3.geth.personal.unlock_account(from_account, passwd)

def store_id_cid_on_blockchain(file_id, receive):
    transaction = contract.functions.storeFileIdToCid(file_id, receive).transact({
        'from': from_account
    })
    txn_receipt = w3.eth.wait_for_transaction_receipt(transaction)
    print(f'Transaction receipts have been mined: \n{txn_receipt}')
    print("File CID link successful!")

def store_id_hash_on_blockchain(file_id, receive):
    transaction = contract.functions.storeFileIdToHash(file_id, receive).transact({
        'from': from_account
    })
    txn_receipt = w3.eth.wait_for_transaction_receipt(transaction)
    print(f'Transaction receipts have been mined: \n{txn_receipt}')
    print("File hash and digital signature link successfully!")

def store_id_public_pem_on_blockchain(file_id, receive):
    transaction = contract.functions.storeUserIdToSignature(file_id, receive).transact({
        'from': from_account
    })
    txn_receipt = w3.eth.wait_for_transaction_receipt(transaction)
    print(f'Transaction receipts have been mined: \n{txn_receipt}')
    print("User digital signature public key link successfully!")

def store_id_sky_on_blockchain(file_id, receive):
    transaction = contract.functions.storeUserIdToAccess(file_id, receive).transact({
        'from': from_account
    })
    txn_receipt = w3.eth.wait_for_transaction_receipt(transaction)
    print(f'Transaction receipts have been mined: \n{txn_receipt}')
    print("User properties private key link success!")


def callback(ch, method, properties, body):
    time.sleep(2)
    receive = body.decode('utf-8')
    if len(receive) <= 70:
        try:
            id_str, cid = receive.split(' - CID: ')
            file_id = int(id_str.split('ID: ')[1]) # 提取文件ID
            file_cid = cid
            print(f"Received successfully! The ID of the file is: {file_id} and the CID of the file is: {file_cid}.")
            # 调用上传到区块链的函数
            store_id_cid_on_blockchain(int(file_id), file_cid)
            print("The ID and CID corresponding to the file have been stored to the blockchain")
        except Exception as e:
            print(f"An error occurred while processing the received data format. Error:{e}")

    elif len(receive) > 70 and len(receive) < 490:
        try:
            id_str, public_pem = receive.split(' - public_pem: ')
            user_id = int(id_str.split('ID: ')[1]) # 提取用户ID
            public_key = public_pem
            print(f"Received successfully! The user ID is {user_id}, and the digital signature public key is: {public_key}")
            # 调用上传到区块链的函数
            store_id_public_pem_on_blockchain(int(user_id), public_key)
            print("The user ID and digitally signed public key are stored on the blockchain.")
        except Exception as e:
            print(f"An error occurred while processing the received data format. Error: {e}")

    elif len(receive) > 1000:
        try:
            id_str, sk = receive.split(' - sk_key: ')
            user_id = int(id_str.split('ID: ')[1]) # 提取用户ID
            sk_key = sk
            print(f"Received successfully! The user ID is {user_id} and the attribute private key is {sk_key}.")
            # 调用上传到区块链的函数
            store_id_sky_on_blockchain(int(user_id), sk_key)
            print("The user ID and attribute private key have been stored to the blockchain")
        except Exception as e:
            print(f"An error occurred while processing the received data format. Error: {e}")
            
    else:
        try:
            id_str, hash_signature_str = receive.split(' - Hash: ')
            file_id = int(id_str.split('ID: ')[1]) # 提取文件ID
            file_hash = 'Hash: ' + hash_signature_str
            print(f"Received successfully! File ID is: {file_id}, file hash and subsequent contents are: {file_hash}")
            # 调用上传到区块链的函数
            store_id_hash_on_blockchain(int(file_id), file_hash)
            print("The file's corresponding ID,Hash, and signature have been stored to the blockchain.")
        except Exception as e:
            print(f"An error occurred while processing the received data format. Error: {e}")

connection = pika.BlockingConnection(connection_parameters)
channel = connection.channel()
queue_name = 'file_upload_queue'
channel.queue_declare(queue=queue_name)
channel.basic_consume(queue=queue_name, on_message_callback=callback, auto_ack=True)
print('Waiting for messages. To exit press CTRL+C')
channel.start_consuming()
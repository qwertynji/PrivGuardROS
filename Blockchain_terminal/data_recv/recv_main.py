# -*- coding: utf-8 -*-
import time
from redis_flush import Recv_data
import threading
from socket import *
lines = []
recv_threads = []
from chain_operations import Ethereum_info_get
from web3 import Web3
host, port = "0.0.0.0", 5500

def get_CID(file_ID):
    w3 = Web3(Web3.HTTPProvider('http://localhost:8545'))
    # 检查节点同步状态
    sync_status = w3.eth.syncing
    if sync_status:
        print(f"dnagqiankuaishu : {sync_status['currentBlock']}, zuigaokuaishu: {sync_status['highestBlock']}")
    else:
        print("The node is fully synchronized to the latest block.")
    contract_address = '0x4bb741A28933b047a2a06E2cDC66E5cc64c07948'
    contract_abi = [{"constant":True,"inputs":[{"internalType":"uint256","name":"","type":"uint256"}],"name":"fileIdToCid","outputs":[{"internalType":"string","name":"","type":"string"}],"payable":False,"stateMutability":"view","type":"function"},{"constant":True,"inputs":[{"internalType":"uint256","name":"","type":"uint256"}],"name":"fileIdToHash","outputs":[{"internalType":"string","name":"","type":"string"}],"payable":False,"stateMutability":"view","type":"function"},{"constant":True,"inputs":[{"internalType":"uint256","name":"fileId","type":"uint256"}],"name":"getFileCid","outputs":[{"internalType":"string","name":"","type":"string"}],"payable":False,"stateMutability":"view","type":"function"},{"constant":True,"inputs":[{"internalType":"uint256","name":"fileId","type":"uint256"}],"name":"getFileHash","outputs":[{"internalType":"string","name":"","type":"string"}],"payable":False,"stateMutability":"view","type":"function"},{"constant":True,"inputs":[{"internalType":"uint256","name":"userId","type":"uint256"}],"name":"getUserAccess","outputs":[{"internalType":"string","name":"","type":"string"}],"payable":False,"stateMutability":"view","type":"function"},{"constant":True,"inputs":[{"internalType":"uint256","name":"userId","type":"uint256"}],"name":"getUserSignature","outputs":[{"internalType":"string","name":"","type":"string"}],"payable":False,"stateMutability":"view","type":"function"},{"constant":False,"inputs":[{"internalType":"uint256","name":"fileId","type":"uint256"},{"internalType":"string","name":"cid","type":"string"}],"name":"storeFileIdToCid","outputs":[],"payable":False,"stateMutability":"nonpayable","type":"function"},{"constant":False,"inputs":[{"internalType":"uint256","name":"fileId","type":"uint256"},{"internalType":"string","name":"hash","type":"string"}],"name":"storeFileIdToHash","outputs":[],"payable":False,"stateMutability":"nonpayable","type":"function"},{"constant":False,"inputs":[{"internalType":"uint256","name":"userId","type":"uint256"},{"internalType":"string","name":"access","type":"string"}],"name":"storeUserIdToAccess","outputs":[],"payable":False,"stateMutability":"nonpayable","type":"function"},{"constant":False,"inputs":[{"internalType":"uint256","name":"userId","type":"uint256"},{"internalType":"string","name":"signature","type":"string"}],"name":"storeUserIdToSignature","outputs":[],"payable":False,"stateMutability":"nonpayable","type":"function"},{"constant":True,"inputs":[{"internalType":"uint256","name":"","type":"uint256"}],"name":"userIdToAccess","outputs":[{"internalType":"string","name":"","type":"string"}],"payable":False,"stateMutability":"view","type":"function"},{"constant":True,"inputs":[{"internalType":"uint256","name":"","type":"uint256"}],"name":"userIdToSignature","outputs":[{"internalType":"string","name":"","type":"string"}],"payable":False,"stateMutability":"view","type":"function"}]
    contract = w3.eth.contract(address=contract_address, abi=contract_abi)
    try:
        file_ID_int = int(file_ID)
        file_cid = contract.functions.getFileCid(file_ID_int).call()
        return file_cid
    except Exception as e:
        print(f'cuowu: {e}')
        exit(1)

def get_hash(file_ID):
    w3 = Web3(Web3.HTTPProvider('http://localhost:8545'))
    # 检查节点同步状态
    sync_status = w3.eth.syncing
    if sync_status:
        print(f"Current block number: {sync_status['currentBlock']}, highest block number: {sync_status['highestBlock']}")
    else:
        print("The node is fully synchronized to the latest block")
    contract_address = '0x4bb741A28933b047a2a06E2cDC66E5cc64c07948'
    contract_abi = [{"constant":True,"inputs":[{"internalType":"uint256","name":"","type":"uint256"}],"name":"fileIdToCid","outputs":[{"internalType":"string","name":"","type":"string"}],"payable":False,"stateMutability":"view","type":"function"},{"constant":True,"inputs":[{"internalType":"uint256","name":"","type":"uint256"}],"name":"fileIdToHash","outputs":[{"internalType":"string","name":"","type":"string"}],"payable":False,"stateMutability":"view","type":"function"},{"constant":True,"inputs":[{"internalType":"uint256","name":"fileId","type":"uint256"}],"name":"getFileCid","outputs":[{"internalType":"string","name":"","type":"string"}],"payable":False,"stateMutability":"view","type":"function"},{"constant":True,"inputs":[{"internalType":"uint256","name":"fileId","type":"uint256"}],"name":"getFileHash","outputs":[{"internalType":"string","name":"","type":"string"}],"payable":False,"stateMutability":"view","type":"function"},{"constant":True,"inputs":[{"internalType":"uint256","name":"userId","type":"uint256"}],"name":"getUserAccess","outputs":[{"internalType":"string","name":"","type":"string"}],"payable":False,"stateMutability":"view","type":"function"},{"constant":True,"inputs":[{"internalType":"uint256","name":"userId","type":"uint256"}],"name":"getUserSignature","outputs":[{"internalType":"string","name":"","type":"string"}],"payable":False,"stateMutability":"view","type":"function"},{"constant":False,"inputs":[{"internalType":"uint256","name":"fileId","type":"uint256"},{"internalType":"string","name":"cid","type":"string"}],"name":"storeFileIdToCid","outputs":[],"payable":False,"stateMutability":"nonpayable","type":"function"},{"constant":False,"inputs":[{"internalType":"uint256","name":"fileId","type":"uint256"},{"internalType":"string","name":"hash","type":"string"}],"name":"storeFileIdToHash","outputs":[],"payable":False,"stateMutability":"nonpayable","type":"function"},{"constant":False,"inputs":[{"internalType":"uint256","name":"userId","type":"uint256"},{"internalType":"string","name":"access","type":"string"}],"name":"storeUserIdToAccess","outputs":[],"payable":False,"stateMutability":"nonpayable","type":"function"},{"constant":False,"inputs":[{"internalType":"uint256","name":"userId","type":"uint256"},{"internalType":"string","name":"signature","type":"string"}],"name":"storeUserIdToSignature","outputs":[],"payable":False,"stateMutability":"nonpayable","type":"function"},{"constant":True,"inputs":[{"internalType":"uint256","name":"","type":"uint256"}],"name":"userIdToAccess","outputs":[{"internalType":"string","name":"","type":"string"}],"payable":False,"stateMutability":"view","type":"function"},{"constant":True,"inputs":[{"internalType":"uint256","name":"","type":"uint256"}],"name":"userIdToSignature","outputs":[{"internalType":"string","name":"","type":"string"}],"payable":False,"stateMutability":"view","type":"function"}]
    contract = w3.eth.contract(address=contract_address, abi=contract_abi)
    try:
        file_ID_int = int(file_ID)
        file_hash = contract.functions.getFileHash(file_ID_int).call()
        return file_hash
    except Exception as e:
        print(f'Abnormal interrupt! Error message: {e}')
        exit(1)

def get_access(user_ID):
    w3 = Web3(Web3.HTTPProvider('http://localhost:8545'))
    # 检查节点同步状态
    sync_status = w3.eth.syncing
    if sync_status:
        print(f"Current block number: {sync_status['currentBlock']}, highest block number: {sync_status['highestBlock']}")
    else:
        print("The node is fully synchronized to the latest block.")
    contract_address = '0x4bb741A28933b047a2a06E2cDC66E5cc64c07948'
    contract_abi = [{"constant":True,"inputs":[{"internalType":"uint256","name":"","type":"uint256"}],"name":"fileIdToCid","outputs":[{"internalType":"string","name":"","type":"string"}],"payable":False,"stateMutability":"view","type":"function"},{"constant":True,"inputs":[{"internalType":"uint256","name":"","type":"uint256"}],"name":"fileIdToHash","outputs":[{"internalType":"string","name":"","type":"string"}],"payable":False,"stateMutability":"view","type":"function"},{"constant":True,"inputs":[{"internalType":"uint256","name":"fileId","type":"uint256"}],"name":"getFileCid","outputs":[{"internalType":"string","name":"","type":"string"}],"payable":False,"stateMutability":"view","type":"function"},{"constant":True,"inputs":[{"internalType":"uint256","name":"fileId","type":"uint256"}],"name":"getFileHash","outputs":[{"internalType":"string","name":"","type":"string"}],"payable":False,"stateMutability":"view","type":"function"},{"constant":True,"inputs":[{"internalType":"uint256","name":"userId","type":"uint256"}],"name":"getUserAccess","outputs":[{"internalType":"string","name":"","type":"string"}],"payable":False,"stateMutability":"view","type":"function"},{"constant":True,"inputs":[{"internalType":"uint256","name":"userId","type":"uint256"}],"name":"getUserSignature","outputs":[{"internalType":"string","name":"","type":"string"}],"payable":False,"stateMutability":"view","type":"function"},{"constant":False,"inputs":[{"internalType":"uint256","name":"fileId","type":"uint256"},{"internalType":"string","name":"cid","type":"string"}],"name":"storeFileIdToCid","outputs":[],"payable":False,"stateMutability":"nonpayable","type":"function"},{"constant":False,"inputs":[{"internalType":"uint256","name":"fileId","type":"uint256"},{"internalType":"string","name":"hash","type":"string"}],"name":"storeFileIdToHash","outputs":[],"payable":False,"stateMutability":"nonpayable","type":"function"},{"constant":False,"inputs":[{"internalType":"uint256","name":"userId","type":"uint256"},{"internalType":"string","name":"access","type":"string"}],"name":"storeUserIdToAccess","outputs":[],"payable":False,"stateMutability":"nonpayable","type":"function"},{"constant":False,"inputs":[{"internalType":"uint256","name":"userId","type":"uint256"},{"internalType":"string","name":"signature","type":"string"}],"name":"storeUserIdToSignature","outputs":[],"payable":False,"stateMutability":"nonpayable","type":"function"},{"constant":True,"inputs":[{"internalType":"uint256","name":"","type":"uint256"}],"name":"userIdToAccess","outputs":[{"internalType":"string","name":"","type":"string"}],"payable":False,"stateMutability":"view","type":"function"},{"constant":True,"inputs":[{"internalType":"uint256","name":"","type":"uint256"}],"name":"userIdToSignature","outputs":[{"internalType":"string","name":"","type":"string"}],"payable":False,"stateMutability":"view","type":"function"}]
    contract = w3.eth.contract(address=contract_address, abi=contract_abi)
    try:
        user_ID_int = int(user_ID)
        file_sk = contract.functions.getUserAccess(user_ID_int).call()
        return file_sk
    except Exception as e:
        print(f'Abnormal interrupt! Error Message: {e}')
        exit(1)

def get_signature(user_ID):
    w3 = Web3(Web3.HTTPProvider('http://localhost:8545'))
    # 检查节点同步状态
    sync_status = w3.eth.syncing
    if sync_status:
        print(f"Current block number: {sync_status['currentBlock']}, highest block number: {sync_status['highestBlock']}")
    else:
        print("The node is fully synchronized to the latest block")
    contract_address = '0x4bb741A28933b047a2a06E2cDC66E5cc64c07948'
    contract_abi = [{"constant":True,"inputs":[{"internalType":"uint256","name":"","type":"uint256"}],"name":"fileIdToCid","outputs":[{"internalType":"string","name":"","type":"string"}],"payable":False,"stateMutability":"view","type":"function"},{"constant":True,"inputs":[{"internalType":"uint256","name":"","type":"uint256"}],"name":"fileIdToHash","outputs":[{"internalType":"string","name":"","type":"string"}],"payable":False,"stateMutability":"view","type":"function"},{"constant":True,"inputs":[{"internalType":"uint256","name":"fileId","type":"uint256"}],"name":"getFileCid","outputs":[{"internalType":"string","name":"","type":"string"}],"payable":False,"stateMutability":"view","type":"function"},{"constant":True,"inputs":[{"internalType":"uint256","name":"fileId","type":"uint256"}],"name":"getFileHash","outputs":[{"internalType":"string","name":"","type":"string"}],"payable":False,"stateMutability":"view","type":"function"},{"constant":True,"inputs":[{"internalType":"uint256","name":"userId","type":"uint256"}],"name":"getUserAccess","outputs":[{"internalType":"string","name":"","type":"string"}],"payable":False,"stateMutability":"view","type":"function"},{"constant":True,"inputs":[{"internalType":"uint256","name":"userId","type":"uint256"}],"name":"getUserSignature","outputs":[{"internalType":"string","name":"","type":"string"}],"payable":False,"stateMutability":"view","type":"function"},{"constant":False,"inputs":[{"internalType":"uint256","name":"fileId","type":"uint256"},{"internalType":"string","name":"cid","type":"string"}],"name":"storeFileIdToCid","outputs":[],"payable":False,"stateMutability":"nonpayable","type":"function"},{"constant":False,"inputs":[{"internalType":"uint256","name":"fileId","type":"uint256"},{"internalType":"string","name":"hash","type":"string"}],"name":"storeFileIdToHash","outputs":[],"payable":False,"stateMutability":"nonpayable","type":"function"},{"constant":False,"inputs":[{"internalType":"uint256","name":"userId","type":"uint256"},{"internalType":"string","name":"access","type":"string"}],"name":"storeUserIdToAccess","outputs":[],"payable":False,"stateMutability":"nonpayable","type":"function"},{"constant":False,"inputs":[{"internalType":"uint256","name":"userId","type":"uint256"},{"internalType":"string","name":"signature","type":"string"}],"name":"storeUserIdToSignature","outputs":[],"payable":False,"stateMutability":"nonpayable","type":"function"},{"constant":True,"inputs":[{"internalType":"uint256","name":"","type":"uint256"}],"name":"userIdToAccess","outputs":[{"internalType":"string","name":"","type":"string"}],"payable":False,"stateMutability":"view","type":"function"},{"constant":True,"inputs":[{"internalType":"uint256","name":"","type":"uint256"}],"name":"userIdToSignature","outputs":[{"internalType":"string","name":"","type":"string"}],"payable":False,"stateMutability":"view","type":"function"}]
    contract = w3.eth.contract(address=contract_address, abi=contract_abi)
    try:
        user_ID_int = int(user_ID)
        user_signature = contract.functions.getUserSignature(user_ID_int).call()
        return user_signature
    except Exception as e:
        print(f'Abnormal interrupt! Error message:{e}')
        exit(1)

if __name__ == '__main__':
    TCP_Socket = socket(AF_INET, SOCK_STREAM)
    TCP_Socket.bind(('0.0.0.0', 5500))
    TCP_Socket.settimeout(10000000)
    TCP_Socket.listen(201)
    print("listening...")
    token, accounts = Ethereum_info_get()
    sem = threading.Semaphore(10)
    lock = threading.Lock()
    for i in range(10):
        recv_threads.append(threading.Thread(target=Recv_data,args=(TCP_Socket,sem,lock,token,accounts,)))
    try:
        for i in range(10):
            recv_threads[i].start()
        for i in range(10):
            recv_threads[i].join(timeout=5)
    except RuntimeError:
        time.sleep(10)
    try:
        TCP_Socket.close()
        time.sleep(25)
        TCP_Socket = socket(AF_INET, SOCK_STREAM)
        TCP_Socket.bind(('0.0.0.0', 5502))
        TCP_Socket.listen(5)
        print("Server started successfully, waiting for connection...")
        while True:
            client_socket, client_address = TCP_Socket.accept()
            print(f"A connection is established with {client_address}")
            while True:
                try:
                    data = client_socket.recv(1024).decode()
                    if not data:
                        print("No data received, connection closed")
                        break
                    if data.endswith('!'):
                        data = data[:-1]
                        file_ID = int(data)
                        print("file_ID_out:", file_ID)
                        response = get_hash(file_ID).encode()
                    elif data.endswith('#'):
                        data = data[:-1]
                        user_ID = int(data)
                        print("user_ID_out:", user_ID)
                        response = get_access(user_ID).encode('utf-8')
                    elif data.endswith('$'):
                        data = data[:-1]
                        user_ID = int(data)
                        print("user_ID_out:", user_ID)
                        response = get_signature(user_ID).encode('utf-8')
                    else:
                        file_ID = int(data)
                        print("file_ID_out:", file_ID)
                        response = get_CID(file_ID).encode()
                    client_socket.sendall(response)
                except Exception as e:
                    print(f"An exception occurs while processing data: {e}")
                    break
            client_socket.close()
            print("The client connection is closed.")
    except KeyboardInterrupt:
        print("The server has been manually shut down.")
    finally:
        TCP_Socket.close()
        print("The server socket is closed.")
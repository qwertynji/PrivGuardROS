import time

import requests
import web3
from web3 import Web3
import json
from solcx import compile_source
from solcx import set_solc_version
from socket import *
import random
import multiprocessing
import sm4


URI = '127.0.0.1'
port1 = 9092
port2 = 8850
port3 = 9999
first_load = True
threads = []


class MESG_Send(object):
    def __init__(self, ip, port):
        local_addr = (ip, port1)
        self.ip = ip
        self.port = port
        self.udp_socket = socket(AF_INET, SOCK_DGRAM)
        self.udp_socket.bind(local_addr)
        self.dest_addr = (ip, port)

    def send_msg(self, msg):
        send_data = msg
        self.udp_socket.sendto(send_data.encode('utf-8'), self.dest_addr)
        self.udp_socket.close()


def Ethereum_info_get():
    w3 = Web3(Web3.HTTPProvider('http://localhost:8545'))
    # 加载合约账户
    accounts = w3.eth.accounts
    # 加载合约
    contract_address = '0xFC0eF805bD6d610420d9f5C5e1Db09F3f2b971d8'
    contract_abi = [{"inputs":[],"payable":False,"stateMutability":"nonpayable","type":"constructor"},{"constant":True,"inputs":[],"name":"ROSCount","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"payable":False,"stateMutability":"view","type":"function"},{"constant":True,"inputs":[{"internalType":"uint256","name":"","type":"uint256"}],"name":"User_addresses","outputs":[{"internalType":"address payable","name":"","type":"address"}],"payable":False,"stateMutability":"view","type":"function"},{"constant":True,"inputs":[{"internalType":"address","name":"","type":"address"}],"name":"Users","outputs":[{"internalType":"address payable","name":"rosaddress","type":"address"},{"internalType":"bool","name":"isRegistered","type":"bool"},{"internalType":"uint256","name":"enode","type":"uint256"},{"internalType":"bytes","name":"token","type":"bytes"}],"payable":False,"stateMutability":"view","type":"function"},{"constant":True,"inputs":[{"internalType":"uint256","name":"","type":"uint256"},{"internalType":"uint256","name":"","type":"uint256"}],"name":"ciphertext","outputs":[{"internalType":"bytes","name":"","type":"bytes"}],"payable":False,"stateMutability":"view","type":"function"},{"constant":True,"inputs":[{"internalType":"bytes","name":"token","type":"bytes"},{"internalType":"address","name":"from","type":"address"}],"name":"data_query_all","outputs":[{"internalType":"bytes[]","name":"","type":"bytes[]"}],"payable":False,"stateMutability":"view","type":"function"},{"constant":True,"inputs":[{"internalType":"bytes","name":"token","type":"bytes"},{"internalType":"bytes","name":"utime","type":"bytes"}],"name":"data_query_by_time_stamp","outputs":[{"internalType":"bytes","name":"","type":"bytes"}],"payable":False,"stateMutability":"view","type":"function"},{"constant":False,"inputs":[],"name":"eth_apply_for","outputs":[{"internalType":"bool","name":"","type":"bool"}],"payable":False,"stateMutability":"nonpayable","type":"function"},{"constant":False,"inputs":[{"internalType":"address","name":"to","type":"address"}],"name":"grant_authority","outputs":[],"payable":False,"stateMutability":"nonpayable","type":"function"},{"constant":True,"inputs":[{"internalType":"address","name":"from","type":"address"},{"internalType":"bytes","name":"token","type":"bytes"}],"name":"isExistToken","outputs":[{"internalType":"bool","name":"","type":"bool"}],"payable":False,"stateMutability":"view","type":"function"},{"constant":False,"inputs":[{"internalType":"bytes","name":"token","type":"bytes"}],"name":"register","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"payable":False,"stateMutability":"nonpayable","type":"function"},{"constant":True,"inputs":[{"internalType":"uint256","name":"","type":"uint256"},{"internalType":"uint256","name":"","type":"uint256"}],"name":"t_ciphertext","outputs":[{"internalType":"bytes","name":"","type":"bytes"}],"payable":False,"stateMutability":"view","type":"function"},{"constant":True,"inputs":[{"internalType":"uint256","name":"","type":"uint256"},{"internalType":"uint256","name":"","type":"uint256"}],"name":"token_List","outputs":[{"internalType":"bytes","name":"","type":"bytes"}],"payable":False,"stateMutability":"view","type":"function"},{"constant":False,"inputs":[{"internalType":"bytes","name":"ctext","type":"bytes"},{"internalType":"bytes","name":"token","type":"bytes"},{"internalType":"bytes","name":"utime","type":"bytes"}],"name":"upload_data","outputs":[],"payable":False,"stateMutability":"nonpayable","type":"function"},{"constant":True,"inputs":[{"internalType":"uint256","name":"","type":"uint256"},{"internalType":"uint256","name":"","type":"uint256"}],"name":"upload_time","outputs":[{"internalType":"bytes","name":"","type":"bytes"}],"payable":False,"stateMutability":"view","type":"function"}]
    token = load_via_artifact(w3, contract_address, contract_abi)
    return token, accounts


# 根据本地链码的二进制文件以及以太坊上的链码部署地址初始化合约
def load_via_artifact(w3, contract_address, contract_abi):
    # Web3实例
    w3 = Web3(Web3.HTTPProvider('http://localhost:8545'))
    # 智能合约地址和ABI
    contract_address = '0xFC0eF805bD6d610420d9f5C5e1Db09F3f2b971d8'
    contract_abi = [{"inputs":[],"payable":False,"stateMutability":"nonpayable","type":"constructor"},{"constant":True,"inputs":[],"name":"ROSCount","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"payable":False,"stateMutability":"view","type":"function"},{"constant":True,"inputs":[{"internalType":"uint256","name":"","type":"uint256"}],"name":"User_addresses","outputs":[{"internalType":"address payable","name":"","type":"address"}],"payable":False,"stateMutability":"view","type":"function"},{"constant":True,"inputs":[{"internalType":"address","name":"","type":"address"}],"name":"Users","outputs":[{"internalType":"address payable","name":"rosaddress","type":"address"},{"internalType":"bool","name":"isRegistered","type":"bool"},{"internalType":"uint256","name":"enode","type":"uint256"},{"internalType":"bytes","name":"token","type":"bytes"}],"payable":False,"stateMutability":"view","type":"function"},{"constant":True,"inputs":[{"internalType":"uint256","name":"","type":"uint256"},{"internalType":"uint256","name":"","type":"uint256"}],"name":"ciphertext","outputs":[{"internalType":"bytes","name":"","type":"bytes"}],"payable":False,"stateMutability":"view","type":"function"},{"constant":True,"inputs":[{"internalType":"bytes","name":"token","type":"bytes"},{"internalType":"address","name":"from","type":"address"}],"name":"data_query_all","outputs":[{"internalType":"bytes[]","name":"","type":"bytes[]"}],"payable":False,"stateMutability":"view","type":"function"},{"constant":True,"inputs":[{"internalType":"bytes","name":"token","type":"bytes"},{"internalType":"bytes","name":"utime","type":"bytes"}],"name":"data_query_by_time_stamp","outputs":[{"internalType":"bytes","name":"","type":"bytes"}],"payable":False,"stateMutability":"view","type":"function"},{"constant":False,"inputs":[],"name":"eth_apply_for","outputs":[{"internalType":"bool","name":"","type":"bool"}],"payable":False,"stateMutability":"nonpayable","type":"function"},{"constant":False,"inputs":[{"internalType":"address","name":"to","type":"address"}],"name":"grant_authority","outputs":[],"payable":False,"stateMutability":"nonpayable","type":"function"},{"constant":True,"inputs":[{"internalType":"address","name":"from","type":"address"},{"internalType":"bytes","name":"token","type":"bytes"}],"name":"isExistToken","outputs":[{"internalType":"bool","name":"","type":"bool"}],"payable":False,"stateMutability":"view","type":"function"},{"constant":False,"inputs":[{"internalType":"bytes","name":"token","type":"bytes"}],"name":"register","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"payable":False,"stateMutability":"nonpayable","type":"function"},{"constant":True,"inputs":[{"internalType":"uint256","name":"","type":"uint256"},{"internalType":"uint256","name":"","type":"uint256"}],"name":"t_ciphertext","outputs":[{"internalType":"bytes","name":"","type":"bytes"}],"payable":False,"stateMutability":"view","type":"function"},{"constant":True,"inputs":[{"internalType":"uint256","name":"","type":"uint256"},{"internalType":"uint256","name":"","type":"uint256"}],"name":"token_List","outputs":[{"internalType":"bytes","name":"","type":"bytes"}],"payable":False,"stateMutability":"view","type":"function"},{"constant":False,"inputs":[{"internalType":"bytes","name":"ctext","type":"bytes"},{"internalType":"bytes","name":"token","type":"bytes"},{"internalType":"bytes","name":"utime","type":"bytes"}],"name":"upload_data","outputs":[],"payable":False,"stateMutability":"nonpayable","type":"function"},{"constant":True,"inputs":[{"internalType":"uint256","name":"","type":"uint256"},{"internalType":"uint256","name":"","type":"uint256"}],"name":"upload_time","outputs":[{"internalType":"bytes","name":"","type":"bytes"}],"payable":False,"stateMutability":"view","type":"function"}]
    # 创建合约实例
    contract = w3.eth.contract(address=contract_address, abi=contract_abi)
    return contract

def register(token, accounts, num, passwd):
    w3 = Web3(Web3.HTTPProvider('http://localhost:8545'))
    w3.geth.personal.unlock_account(accounts[num], '123')
    try:

        receipt = token.functions.register(passwd.encode('utf-8')).transact({'from': accounts[num]})

    except requests.ConnectionError:
        print("Errors in Chain.")
        return False
    except web3.exceptions as e:
        print("Error: ", e)
        return False
    if w3.eth.wait_for_transaction_receipt(receipt).blockHash == '':
        return False
    else:

        return num


def data_on_chain_cop(token, accounts, cpi, num, passwd):
    w3 = Web3(Web3.HTTPProvider('http://localhost:8545'))
    w3.geth.personal.unlock_account(accounts[num], '123')
    stmp = time.time()
    date = time.localtime(stmp)
    format_time = time.strftime('%Y-%m-%d %H:%M:%S', date)
    try:
       # receipt = token.functions.upload_data(Web3.toBytes(text=str(cpi)),Web3.toBytes(text=str(passwd)),Web3.toBytes(text=str(format_time))).transact({'from': accounts[num]})
       receipt = token.functions.upload_data(str(cpi).encode('utf-8'),str(passwd).encode('utf-8'),str(format_time).encode('utf-8')).transact({'from': accounts[num]})
    except requests.ConnectionError:
        print("Errors in Chain.")
        return False
    except web3.exceptions:
        print("You have registered! or insufficient funds, please check.")
        return False
    if w3.eth.wait_for_transaction_receipt(receipt).blockHash == '':
        return False
    else:
        return True


def Info_Check(token, accounts, num, passwd, address_num):
    w3 = Web3(Web3.HTTPProvider('http://localhost:8545'))
    w3.geth.personal.unlock_account(accounts[num], '123')
    w3.geth.personal.unlock_account(accounts[address_num], '123')
    return token.functions.data_query_all(passwd.encode('utf-8'), accounts[address_num]).call({'from': accounts[num]})

def Authority_Grant(token, accounts, num, address_num):
    w3 = Web3(Web3.HTTPProvider('http://localhost:8545'))
    w3.geth.personal.unlock_account(accounts[num], '123')
    w3.geth.personal.unlock_account(accounts[address_num], '123')
    print(address_num)
    try:
        receipt = token.functions.grant_authority(accounts[address_num]).transact({'from': accounts[num]})
    except requests.ConnectionError:
        print("Errors in Chain.")
        return False
    except web3.exceptions:
        print("You have registered! or insufficient funds, please check.")
        return False
    if w3.eth.wait_for_transaction_receipt(receipt).blockHash == '':
        return False
    else:
        return True


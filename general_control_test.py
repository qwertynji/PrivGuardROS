import sys
sys.path.append('/home/abc/.local/lib/python3.10/site-packages')
import os
import requests
import time
from socket import *
from pack.BasePacker import BasePacker
from charm.toolbox.pairinggroup import PairingGroup, GT,serialize,deserialize
from charm.toolbox.ABEnc import ABEnc
from charm.adapters.kpabenc_adapt_hybrid import HybridABEnc
from charm.toolbox.symcrypto import AuthenticatedCryptoAbstraction
from charm.schemes.abenc.abenc_lsw08 import KPabe
from charm.toolbox.secretutil import SecretUtil
from charm.core.engine.util import objectToBytes, bytesToObject
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import socket as sk
import random
import pika
import uuid

#TCP/IP实例
tcp_cli = socket(AF_INET,SOCK_STREAM)
# #目标IP/Port
ip = '8.134.222.175'
port = 5500

# Producer 类定义保持不变
class Producer:
    def __init__(self, rabbitmq_host, queue_name):
        self.connection = pika.BlockingConnection(
            pika.ConnectionParameters(host=rabbitmq_host))
        self.channel = self.connection.channel()
        self.queue_name = queue_name
    def call(self, message):
        corr_id = str(uuid.uuid4())
        self.channel.basic_publish(
            exchange='',
            routing_key=self.queue_name,
            properties=pika.BasicProperties(
                correlation_id=corr_id,
            ),
            body=message)

rabbitmq_host = '8.138.56.15'  # 消息队列服务地址
queue_name = 'file_upload_queue'  # 消息队列名称
producer = Producer(rabbitmq_host, queue_name)  # 创建消息生产者实例

# 从IPFS下载文件到本地
def download_file_from_ipfs(ipfs_hash, ipfs_url, output_path):
    try:
        full_url = f'http://{ipfs_url}/api/v0/cat?arg={ipfs_hash}'
        response = requests.post(full_url, stream=True)
        if response.status_code == 200:
            print('Connection successful, downloading file...')
            with open(output_path, 'wb') as f:
                for chunk in response.iter_content(chunk_size=4096):
                    f.write(chunk)
            return f'File downloaded successfully, save to:{output_path}'
        else:
            return f'Download failed, status code: {response.status_code}'

    except requests.exceptions.RequestException as e:
        return f'Request error: {e}'
        
def get_file_digest(file_path):
    # 读取文件并返回其SHA-256哈希摘要
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    with open(file_path, 'rb') as file:
        chunk = file.read(4096)
        while chunk:
            chunk = file.read(4096)
            digest.update(chunk)
    return digest.finalize()

def save_hashed_filehex(hashed_file_hex_path, file_path, file_id):
    global digest
    digest = get_file_digest(file_path)
    with open(hashed_file_hex_path, 'w') as file:
        file.write(f"ID: {file_id} - Hash value: {digest.hex()}\n")
    print(f"The mapping between file ID and hash digest has been saved to file {hashed_file_hex_path}!")
    
# 发送文件到服务器  
def send_file_to_server(server_ip, server_port, file_path):
    try:
        file_size = os.path.getsize(file_path)
        sock = sk.socket(sk.AF_INET, sk.SOCK_STREAM)
        print("Trying to establish a connection......")
        sock.connect((server_ip, server_port))
        print("The connection was successfully established! Uploading file......")
        with open(file_path, 'rb') as f:
            file_name = os.path.basename(file_path)
            file_name_bytes = file_name.encode('utf-8')
            sock.sendall(file_name_bytes)
            sock.sendfile(f)
        print('File uploaded successfully')
        return file_size
    except Exception as e:
        print(f'File upload failed: {str(e)}')
        return 0
    finally:
        sock.close()

def upload_file():
    server_ip = '8.138.56.15'
    server_port = 5000
    file_path = input("Please enter the file path to be uploaded: ")
    start_time = time.time()
    file_size = send_file_to_server(server_ip, server_port, file_path)
    end_time = time.time()
    t = end_time - start_time
    if t > 0:
        print(f'{file_size / 1024 / 1024 / t} mb/s')

def receive_and_publish_file():
    try:
            hash = digest.hex()
            producer.call(hash.encode())
            print(f'hash summary {hash} uploaded successfully!')
    except Exception as e:
        print(f'File receiving failure: {str(e)}')

def main():
    # 设定群
    groupObj = PairingGroup('SS512')
    kpabe = KPabe(groupObj)
    hyb_abe = HybridABEnc(kpabe, groupObj)
    (pk, mk) = hyb_abe.setup()
    pk_serialized = objectToBytes(pk, groupObj)
    mk_serialized = objectToBytes(mk, groupObj)
    with open('pk_serialized.pkl', 'wb') as f:
        f.write(pk_serialized)
    with open('mk_serialized.pkl', 'wb') as f:
        f.write(mk_serialized)
    while True:
        print("\n************Welcome to private file safe storage and reliable sharing management system************")
        print("1. Upload file")
        print("2. Get file")
        print("3. Encrypted file")
        print("4. Decrypt file")
        print("5. Calculates the file hash summary and links it to storage")
        print("6. Query file hash summary")
        print("7. Enable topic listening on a node")
        print("8. quit")
        choice = input("Please enter the operation number to be performed: ")
        if choice == "1":
            upload_file()
        elif choice == "2":
            try:
                print("Trying to connect to the blockchain end server......")
                tcp_cli.connect((ip,port))
                print("The connection is successful!")
            except Exception:
                print ('Time out or unknow IP. Please Contact the Administrator.')
                exit(1)
            username = input("Please enter your username:")
            passwd = input("Please enter your password:")
            res = BasePacker.command_send('verification',username=username,passwd=passwd,cli=tcp_cli)
            if not res:
                exit(1)
            print("Authentication successful!")
            if res == True:
                tcp_cli.close()
                time.sleep(80)
                try:
                    tcp_clii = socket(AF_INET,SOCK_STREAM)
                    print("Trying to connect to the blockchain end server......")
                    ipp = '8.134.222.175'
                    portt = 5502
                    tcp_clii.connect((ipp,portt))
                    print("The connection is successful!")
                except Exception:
                    print ('Time out or unknow IP. Please Contact the Administrator.')
                    exit(1)
                file_ID = input("Enter the ID of the file you want to get: ")
                id_to_send = file_ID.encode()
                try:
                    tcp_clii.sendall(id_to_send)
                except Exception as e:
                    print('Failed to send data to the server. Exception:', e)
                    exit(1)
                try:
                    file_ID_int = int(file_ID)
                    try:
                        file_cid = tcp_clii.recv(1024)
                    except Exception as e:
                        print('Failed to receive data from the server. Exception:', e)
                        exit(1)
                    print(f'The CID file is :{file_cid.decode()}')
                except Exception as e:
                    print(f'Error getting file CID: {e}')
                    exit(1)
                ipfs_hash = file_cid.decode()
                ipfs_url = '8.138.56.15:5001'
                output_path = input("请输入文件的保存路径: ")
                download_result = download_file_from_ipfs(ipfs_hash, ipfs_url, output_path)
                print(download_result)
        elif choice == "3":
            file_path = input("Please enter the file path to be encrypted:")
            access_policy = input("Enter a list of properties, separated by commas:").split(',')
            access_key = input("Please enter the access control policy:")
            with open('pk_serialized.pkl', 'rb') as f:
                pk_deserialized = bytesToObject(f.read(), groupObj)
            with open('mk_serialized.pkl', 'rb') as f:
                mk_deserialized = bytesToObject(f.read(), groupObj)
            sk = hyb_abe.keygen(pk_deserialized, mk_deserialized, access_key)
            sk_serialized = objectToBytes(sk, groupObj)
            with open('sk_file', 'wb') as f:
                f.write(sk_serialized)
            with open(file_path, 'rb') as f:
                data = f.read()
            encrypted_data = hyb_abe.encrypt(pk, data, access_policy)
            encrypted_data_serialized = objectToBytes(encrypted_data, groupObj)
            with open('encrypted_file', 'wb') as f:
                f.write(encrypted_data_serialized)
            print("The file is encrypted. The encrypted file path is encrypted_file")
            os.remove(file_path)
            print("Original file deleted")
        elif choice == "4":
            # 设定群
            groupObj = PairingGroup('SS512')
            kpabe = KPabe(groupObj)
            hyb_abe = HybridABEnc(kpabe, groupObj)
            encrypted_file_path = input("Please enter the file path to decrypt: ")
            with open('encrypted_file', 'rb') as f:
                encrypted_data_deserialized = bytesToObject(f.read(), groupObj)
            with open('sk_file', 'rb') as f:
                sk_file_deserialized = bytesToObject(f.read(), groupObj)
            decrypted_data = hyb_abe.decrypt(encrypted_data_deserialized, sk_file_deserialized)
            with open('decrypted_file', 'wb') as f:
                f.write(decrypted_data)
            print("File decryption complete, decrypt file path: decrypted_file")
        elif choice == "5":
            hashed_file_hex_path = 'hashed_file_hex.txt'
            file_path = input("Enter the path to the file where you want to generate the hash summary:") 
            file_id = random.randint(1, 1000000)
            print(f"The file ID for which the hash summary will be generated is: {file_id}")
            save_hashed_filehex(hashed_file_hex_path, file_path, file_id)
            receive_and_publish_file()
        elif choice == "6":
            try:
                print("Trying to connect to the blockchain end server......")
                tcp_cli.connect((ip,port))
                print("The connection is successful!")
            except Exception:
                print ('Time out or unknow IP. Please Contact the Administrator.')
                exit(1)
            username = input("Please enter your username:")
            passwd = input("Please enter your password:")
            res = BasePacker.command_send('verification',username=username,passwd=passwd,cli=tcp_cli)
            if not res:
                exit(1)
            print("Authentication successful!")
            if res == True:
                tcp_cli.close()
                time.sleep(80)
                try:
                    tcp_clii = socket(AF_INET,SOCK_STREAM)
                    print("Trying to connect to the blockchain end server......")
                    ipp = '8.134.222.175'
                    portt = 5502
                    tcp_clii.connect((ipp,portt))
                    print("The connection is successful!")
                except Exception:
                    print ('Time out or unknow IP. Please Contact the Administrator.')
                    exit(1)
                file_ID = input("Enter the ID of the file you want to get (start with !). End):")
                id_to_send = file_ID.encode()
                try:
                    tcp_clii.sendall(id_to_send)
                except Exception as e:
                    print('Failed to send data to the server. Exception:', e)
                    exit(1)
                try:
                    try:
                        file_hash = tcp_clii.recv(1024)
                    except Exception as e:
                        print('Failed to receive data from the server. Exception:', e)
                        exit(1)
                    print(f'The file hash summary is:{file_hash.decode()}')
                except Exception as e:
                    print(f'Error getting file hash summary: {e}')
                    exit(1)
        elif choice == "7":
            try:
                os.popen('./monitor.sh')
            except Exception:
                print ('Script file execution failed!'\
                      'Please give corresponding file execution permission!')
                exit(1)
        elif choice == "8":
            print("Thanks for using!")
            break
        else:
            print("Invalid input, please re-enter")

if __name__ == "__main__":
    main()

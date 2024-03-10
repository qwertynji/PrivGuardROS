import sys
sys.path.append('/home/abc/.local/lib/python3.10/site-packages')
import os
import requests
import time
from socket import *
import re
from pack.BasePacker import BasePacker
from charm.toolbox.pairinggroup import PairingGroup, GT,serialize,deserialize
from charm.toolbox.secretutil import SecretUtil
from charm.toolbox.ABEnc import ABEnc  # 假设属性基加密库
from charm.adapters.abenc_adapt_hybrid import HybridABEnc  # 混合加密适配器
from charm.toolbox.symcrypto import AuthenticatedCryptoAbstraction
from charm.schemes.abenc.abenc_lsw08 import KPabe
from charm.core.engine.util import objectToBytes, bytesToObject
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives import serialization, hashes
import socket as sk
import pika
import uuid

#TCP/IP实例
tcp_cli = socket(AF_INET,SOCK_STREAM)
# #目标IP/Port
ip = '8.134.222.175'
port = 5500

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
            return f'The file is downloaded successfully and saved to: {output_path}'
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
            digest.update(chunk)
            chunk = file.read(4096)
    return digest.finalize()

def save_hashed_filehex(hashed_file_hex_path, file_path, file_id, private_key):
    digest = get_file_digest(file_path)
    signature = sign_data(private_key, digest)
    with open(hashed_file_hex_path, 'a') as file:
        file.write(f"ID: {file_id} - Hash: {digest.hex()} - Signature: {signature.hex()}\n")
    print(f"File {file_id}'s hash and signature have been saved to {hashed_file_hex_path}!")

def load_private_key(private_key_path):
    with open(private_key_path, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
            backend=default_backend()
        )
    return private_key

def hash_folder(folder_path, hashed_file_hex_path, private_key_path):
    private_key = load_private_key(private_key_path)
    for root, dirs, files in os.walk(folder_path):
        for file in files:
            file_path = os.path.join(root, file)
            file_name_without_extension, _ = os.path.splitext(file)
            file_id = file_name_without_extension
            save_hashed_filehex(hashed_file_hex_path, file_path, file_id, private_key)
    
FILE_NAME_END = b"\r\n\r\n"

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
            sock.sendall(file_name_bytes + FILE_NAME_END)
            sock.sendfile(f)
        print('File uploaded successfully')
        return file_size
    except Exception as e:
        print(f'File upload failure: {str(e)}')
        return 0
    finally:
        sock.close()

def upload_all_files_in_directory(directory_path):
    server_ip = '8.138.56.15'
    server_port = 5000
    total_file_size = 0
    total_time_spent = 0
    for file_name in os.listdir(directory_path):
        file_path = os.path.join(directory_path, file_name)
        if os.path.isfile(file_path):  # 确认是否是文件
            start_time = time.time()
            file_size = send_file_to_server(server_ip, server_port, file_path)
            end_time = time.time()
            total_file_size += file_size
            total_time_spent += end_time - start_time

def upload_folder(dir_path):
    directory_path = dir_path
    upload_all_files_in_directory(directory_path)

def generate_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    return private_key, private_key.public_key()

def save_keys(private_key, public_key):
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    with open('private_key.pem', 'wb') as f:
        f.write(private_pem)
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open('public_key.pem', 'wb') as f:
        f.write(public_pem)

def sign_data(private_key, data):
    return private_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

def upload_ids_hashes_signatures(file_path, producer):
    with open(file_path, 'r') as file:
        file_content = file.read()
    pattern = re.compile(r"ID: (.+?) - Hash: (.+?) - Signature: (.+?)(?:\n|$)")
    matches = pattern.findall(file_content)
    for match in matches:
        image_id, image_hash, image_signature = match
        message = f"ID: {image_id} - Hash: {image_hash} - Signature: {image_signature}"
        print(f"Ready to upload message......")
        producer.call(message.encode('utf-8'))

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
        print("1. Encrypt data and upload it")
        print("2. Get the data and decrypt it")
        print("3. quit")
        choice = input("Please enter the operation number to be performed:")
        if choice == "1":
            try:
                os.popen('./monitor.sh')
            except Exception:
                print ('Script file execution failed!'\
                      'Please give corresponding file execution permission!')
                exit(1)
            dir_path = input("Please enter the path of the folder to be processed:")
            # 生成密钥对
            private_key, public_key = generate_key_pair()
            save_keys(private_key, public_key)
            user_id = input("Please enter your user ID:")
            pem_file_path = 'public_key.pem'
            with open(pem_file_path, 'rb') as f:
                public_key_data = f.read()
            message = f"userID: {user_id} - public_pem: {public_key_data}"
            producer.call(message.encode('utf-8'))
            # 计算每个文件的哈希摘要和数字签名并保存
            folder_path = dir_path 
            hashed_file_hex_path = 'hashed_file_hex.txt'
            private_key_path = 'private_key.pem'
            hash_folder(folder_path, hashed_file_hex_path, private_key_path)
            file_path = hashed_file_hex_path
            upload_ids_hashes_signatures(file_path, producer)
            access_policy = input("Enter a list of properties, separated by commas:").split(',')
            access_key = input("Please enter the access control policy:")
            with open('pk_serialized.pkl', 'rb') as f:
                pk_deserialized = bytesToObject(f.read(), groupObj)
            with open('mk_serialized.pkl', 'rb') as f:
                mk_deserialized = bytesToObject(f.read(), groupObj)
            # 生成密钥
            sk = hyb_abe.keygen(pk_deserialized, mk_deserialized, access_key)
            sk_serialized = objectToBytes(sk, groupObj)
            with open('sk_file', 'wb') as f:
                f.write(sk_serialized)
            sk_file_path = 'sk_file'
            with open(sk_file_path, 'rb') as f:
                sk_key_data = f.read()
            message_1 = f"userID: {user_id} - sk_key: {sk_key_data}"
            print(f"Ready to upload message......")
            producer.call(message_1.encode('utf-8'))
            os.remove(sk_file_path)
            for root, dirs, files in os.walk(dir_path):
                for file in files:
                    file_path = os.path.join(root, file)
                    with open(file_path, 'rb') as file_to_encrypt:
                        data = file_to_encrypt.read()
                    encrypted_data = hyb_abe.encrypt(pk_deserialized, data, access_policy)
                    encrypted_data_serialized = objectToBytes(encrypted_data, groupObj)
                    encrypted_file_path = os.path.join(root, f"encrypted_{file}")
                    with open(encrypted_file_path, 'wb') as encrypted_file:
                        encrypted_file.write(encrypted_data_serialized)
                    os.remove(file_path)
                    print(f"Encrypted and removed file: {file_path}")
            print("All files are encrypted.")
            upload_folder(dir_path)
        elif choice == "2":
            try:
                print("Trying to connect to the blockchain end server......")
                tcp_cli.connect((ip,port))
                print("The connection is successful!")
            except Exception:
                print ('Time out or unknow IP. Please Contact the Administrator.')
                exit(1)
            username = input("Please enter your username: ")
            passwd = input("Please enter your password: ")
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
                except Exception as e:
                    print(f'Error getting file CID: {e}')
                    exit(1)
                ipfs_hash = file_cid.decode() 
                ipfs_url = '8.138.56.15:5001'
                output_path = "downloaded_file.jpg"
                download_result = download_file_from_ipfs(ipfs_hash, ipfs_url, output_path)
                print(download_result)
            groupObj = PairingGroup('SS512')
            kpabe = KPabe(groupObj)
            hyb_abe = HybridABEnc(kpabe, groupObj)
            encrypted_file_path = '/home/abc/charm-dev/Utlimate/downloaded_file.jpg'
            with open('downloaded_file.jpg', 'rb') as f:
                encrypted_data_deserialized = bytesToObject(f.read(), groupObj)
            tcp_cli.close()
            time.sleep(70)
            try:
                tcp_clii = socket(AF_INET,SOCK_STREAM)
                print("Trying to connect to the blockchain end server......")
                ipp = '8.134.222.175'
                portt = 5502
                tcp_clii.connect((ipp,portt))
                print("连接成功！")
            except Exception:
                print ('Time out or unknow IP. Please Contact the Administrator.')
                exit(1)
            user_ID = input("Please enter your user ID(ending with # ): ")
            id_to_send = user_ID.encode()
            try:
                tcp_clii.sendall(id_to_send)
            except Exception as e:
                print('Failed to send data to the server. Exception:', e)
                exit(1)
            try:
                try:
                    file_sk = tcp_clii.recv(2048)
                    with open('download_sk', 'wb') as f:
                        f.write(file_sk)
                except Exception as e:
                    print('Failed to receive data from the server. Exception:', e)
                    exit(1)
                print(f'The private key is saved in a file: download_sk')
            except Exception as e:
                print(f'Error getting file private key: {e}')
                exit(1)
            with open('download_sk', 'rb') as f:
                file_content = f.read()
                trimmed_content = file_content.strip(b"b'").rstrip(b"'")
                sk_file_deserialized = bytesToObject(trimmed_content, groupObj)
            decrypted_data = hyb_abe.decrypt(encrypted_data_deserialized, sk_file_deserialized)
            with open('decrypted_file.jpg', 'wb') as f:
                f.write(decrypted_data)
            print("File decryption complete, decrypt file path: decrypted_file.jpg")
            tcp_cli.close()
            time.sleep(70)
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
            file_ID = input("Please enter the file ID(start with ! end):")
            id_to_send = file_ID.encode()
            try:
                tcp_clii.sendall(id_to_send)
            except Exception as e:
                print('Failed to send data to the server. Exception:', e)
                exit(1)
            try:
                try:
                    file_hash_signature = tcp_clii.recv(1024)
                    with open('download_file_hash_signature', 'wb') as f:
                        f.write(file_hash_signature)
                except Exception as e:
                    print('Failed to receive data from the server. Exception:', e)
                    exit(1)
                print(f'The hash summary and digital signature are saved in the file: download_file_hash_signature')
            except Exception as e:
                print(f'Error getting file hash summary and digital signature: {e}')
                exit(1)
            hash_file_path = "download_file_hash_signature"
            with open(hash_file_path, "r") as file:
                file_content = file.read()
            hash_value = file_content.split("Hash: ")[1].split(" - Signature:")[0]
            file_path = 'decrypted_file.jpg'
            original_hash = get_file_digest(file_path)
            if hash_value == original_hash.hex():
                print("The hash summary is verified")
            else:
                print("The hash summary validation failed. Procedure")
            tcp_cli.close()
            time.sleep(70)
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
            user_ID = input("Please enter your user ID(ending with $):")
            id_to_send = user_ID.encode()
            try:
                tcp_clii.sendall(id_to_send)
            except Exception as e:
                print('Failed to send data to the server. Exception:', e)
                exit(1)
            try:
                try:
                    user_signature = tcp_clii.recv(1024) 
                    with open('download_user_signature', 'wb') as f:
                        f.write(user_signature)

                except Exception as e:
                    print('Failed to receive data from the server. Exception:', e)
                    exit(1)
                print(f'The digitally signed public key is saved in the file: download_user_signature')
            except Exception as e:
                print(f'Error getting digital signature public key: {e}')
                exit(1)
            file_path = 'download_user_signature'
            with open(file_path, 'rb') as f:
                original_content = f.read()
            content = original_content.decode('utf-8')
            if content.startswith("b'") and content.endswith("'"):
                content = content[2:-1]
            content = content.replace('\\n', '\n')
            with open('download_user_signature.pem', 'w') as f:
                f.write(content)
            with open('download_user_signature.pem', 'rb') as f:
                public_key = serialization.load_pem_public_key(f.read(), backend=default_backend())
            with open('download_file_hash_signature', 'r') as file:
                file_hash_sig = file.read().strip()
            parts = file_hash_sig.split('- Signature: ')
            if len(parts) > 1:
                signature_data = parts[1]
            signature_bytes = bytes.fromhex(signature_data)
            try:
                public_key.verify(
                    signature_bytes,
                    original_hash,
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA256()
                )
                print("Signature is valid.")
            except InvalidSignature:
                print("Signature is invalid.")
        elif choice == "3":
            print("Thanks for using! ")
            break
        else:
            print("Invalid input, please re-enter! ")
            
if __name__ == "__main__":
    main()

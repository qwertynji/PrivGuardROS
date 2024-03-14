import sys
sys.path.append('/home/abc/.local/lib/python3.10/site-packages')
import os
import time
from charm.toolbox.pairinggroup import PairingGroup, serialize, deserialize
from charm.toolbox.secretutil import SecretUtil
from charm.toolbox.ABEnc import ABEnc
from charm.adapters.abenc_adapt_hybrid import HybridABEnc
from charm.schemes.abenc.abenc_lsw08 import KPabe
from charm.core.engine.util import objectToBytes, bytesToObject
import pika
import uuid

# Producer 类定义
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

def encrypt_and_remove_file(file_path, encrypted_files_dir, pk, access_policy, groupObj, hyb_abe):
    start_time = time.time()
    # 读取要加密的文件内容
    with open(file_path, 'rb') as file_to_encrypt:
        data = file_to_encrypt.read()
    # 加密数据
    encrypted_data = hyb_abe.encrypt(pk, data, access_policy)
    encrypted_data_serialized = objectToBytes(encrypted_data, groupObj)
    file_size = len(encrypted_data_serialized)
    # 保存加密后的文件
    encrypted_file_path = os.path.join(encrypted_files_dir, f"encrypted_{os.path.basename(file_path)}")
    with open(encrypted_file_path, 'wb') as encrypted_file:
        encrypted_file.write(encrypted_data_serialized)
    # 删除原始的明文文件
    os.remove(file_path)
    end_time = time.time()
    return file_size, end_time - start_time

def main():
    # 设定群
    groupObj = PairingGroup('SS512')
    kpabe = KPabe(groupObj)
    hyb_abe = HybridABEnc(kpabe, groupObj)
    (pk, mk) = hyb_abe.setup()

    # 序列化
    pk_serialized = objectToBytes(pk, groupObj)
    mk_serialized = objectToBytes(mk, groupObj)

    # 将序列化后的公钥和主钥写入文件
    with open('pk_serialized.pkl', 'wb') as f:
        f.write(pk_serialized)
    with open('mk_serialized.pkl', 'wb') as f:
        f.write(mk_serialized)

    # 接收用户输入的属性列表
    access_policy = ['A', 'B', 'C']
    # access_key = "(A or (B and C))"

    # 反序列化（读取）公钥和主钥
    with open('pk_serialized.pkl', 'rb') as f:
        pk_deserialized = bytesToObject(f.read(), groupObj)
    # 将获取的数据进行加密
    dir_path = '/home/abc/charm-dev/Utlimate/imagedata_1'
    encrypted_dir_path = os.path.join(dir_path, "encrypted")

    # 确保加密后的文件夹存在
    if not os.path.exists(encrypted_dir_path):
        os.makedirs(encrypted_dir_path)

    total_files_encrypted = 0

    # 遍历文件夹并加密所有文件
    encryption_times = []
    encryption_file_sizes = []
    for root, dirs, files in os.walk(dir_path):
        for file in files:
            file_path = os.path.join(root, file)
            # 判断是否应该跳过加密的文件
            if file.startswith("encrypted_") or not os.path.isfile(file_path):
                continue
            file_size, encryption_time = encrypt_and_remove_file(file_path, encrypted_dir_path, pk_deserialized, access_policy, groupObj, hyb_abe)
            encryption_times.append(encryption_time)
            encryption_file_sizes.append(file_size)
            total_files_encrypted += 1

    # 计算性能指标
    total_encryption_time = sum(encryption_times)
    total_encrypted_size = sum(encryption_file_sizes)
    avg_encryption_time = total_encryption_time / len(encryption_times) if encryption_times else 0
    max_encryption_time = max(encryption_times) if encryption_times else 0
    min_encryption_time = min(encryption_times) if encryption_times else 0
    avg_encryption_speed = total_encrypted_size / total_encryption_time if total_encryption_time > 0 else 0
    
    print("All files are encrypted.")
    print(f"Total encryption time: {total_encryption_time} seconds")
    print(f"Average encryption time: {avg_encryption_time} seconds")
    print(f"Maximum encryption time: {max_encryption_time} seconds")
    print(f"Minimum encryption time: {min_encryption_time} seconds")
    print(f"Average encryption rate: {avg_encryption_speed} bytes/second")
    print(f"Total number of encrypted files: {total_files_encrypted}")

if __name__ == "__main__":
    main()  




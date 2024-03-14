from charm.adapters.kpabenc_adapt_hybrid import HybridABEnc
from charm.toolbox.pairinggroup import PairingGroup,GT,extract_key,serialize
from charm.toolbox.symcrypto import AuthenticatedCryptoAbstraction
from charm.toolbox.ABEnc import ABEnc
from charm.schemes.abenc.abenc_lsw08 import KPabe
from charm.toolbox.secretutil import SecretUtil
from charm.core.engine.util import objectToBytes, bytesToObject
import os
import time

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
    
    # 输入待加密的文件夹路径
    folder_path = input("Please enter the folder path to be encrypted: ")
    # 创建新的加密文件夹
    encrypted_folder_path = 'encrypted_files'
    if not os.path.exists(encrypted_folder_path):
        os.makedirs(encrypted_folder_path)

    # 用于存储每次加密所需的时间和处理的总字节数
    encryption_times = []
    total_bytes_encrypted = 0

    # 读取指定文件夹下的所有图像和视频文件
    for filename in os.listdir(folder_path):
        file_path = os.path.join(folder_path, filename)
        # 检查文件扩展名
        if filename.lower().endswith(('.jpg', '.png', '.mp4', '.avi')):
            with open(file_path, 'rb') as f:
                data = f.read()
                file_size = len(data)
                total_bytes_encrypted += file_size

            # 开始计时
            start_time = time.time() 
            access_policy = ['ONE', 'TWO', 'THREE']
            encrypted_data = hyb_abe.encrypt(pk, data, access_policy)
            # 结束计时并计算加密所需时间
            encryption_time = time.time() - start_time
            # 存储加密后的文件
            encrypted_file_path = os.path.join(encrypted_folder_path, f'encrypted_{filename}')
            with open(encrypted_file_path, 'wb') as f:
                f.write(objectToBytes(encrypted_data, groupObj))

            print(f"File '{filename}' is encrypted.")

            # 存储加密时间
            encryption_times.append(encryption_time)

    # 计算加密性能
    total_encryption_time = sum(encryption_times)
    encryption_rate_bytes = total_bytes_encrypted / total_encryption_time if total_encryption_time > 0 else 0

    print(f"Time required for all encryption to succeed: {total_encryption_time} seconds.")
    print(f"Total encrypted bytes: {total_bytes_encrypted} bytes.")
    print(f"Encryption rate: {encryption_rate_bytes} bytes/second.")

if __name__ == "__main__":
    main()
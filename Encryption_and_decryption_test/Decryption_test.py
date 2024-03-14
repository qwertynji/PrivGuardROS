from charm.adapters.kpabenc_adapt_hybrid import HybridABEnc
from charm.toolbox.pairinggroup import PairingGroup, GT, extract_key, serialize
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
    access_key = '((ONE or TWO) and THREE)'
    
    # 反序列化（读取）公钥和主密钥
    with open('pk_serialized.pkl', 'rb') as f:
        pk_deserialized = bytesToObject(f.read(), groupObj)
    with open('mk_serialized.pkl', 'rb') as f:
        mk_deserialized = bytesToObject(f.read(), groupObj)
        
    # 生成密钥
    sk = hyb_abe.keygen(pk_deserialized, mk_deserialized, access_key)
    # 序列化密钥
    sk_serialized = objectToBytes(sk, groupObj)
    # 保存密钥到文件
    with open('sk_file', 'wb') as f:
        f.write(sk_serialized)
    
    # 获取要解密的文件夹路径
    encrypted_folder_path = input("Please enter the folder path to decrypt: ")
    decrypted_folder_path = "decrypted_files"
    
    # 如果解密文件夹不存在，则创建
    if not os.path.exists(decrypted_folder_path):
        os.makedirs(decrypted_folder_path)
    
    # 获取加密文件列表
    encrypted_files = [f for f in os.listdir(encrypted_folder_path) if os.path.isfile(os.path.join(encrypted_folder_path, f))]
    total_files = len(encrypted_files)
    
    start_time = time.time()
    
    for encrypted_file in encrypted_files:
        # 设置加密和解密的文件路径
        encrypted_file_path = os.path.join(encrypted_folder_path, encrypted_file)
        decrypted_file_path = os.path.join(decrypted_folder_path, encrypted_file)
        
        # 从文件中读取序列化加密数据
        with open(encrypted_file_path, 'rb') as infile:
            encrypted_data_deserialized = bytesToObject(infile.read(), groupObj)
        
        # 解密数据
        decrypted_data = hyb_abe.decrypt(encrypted_data_deserialized, sk)
        
        # 将解密后的数据写入新文件夹中的新文件
        with open(decrypted_file_path, 'wb') as outfile:
            outfile.write(decrypted_data)
    
    end_time = time.time()
    
    # 总时间和平均时间计算
    total_time_taken = end_time - start_time
    avg_time_per_file = total_time_taken / total_files if total_files > 0 else 0
    
    print("All files decrypted complete!")
    print(f"Number of decrypted files: {total_files}.")
    print(f"Total decryption time: {total_time_taken:.2f} seconds.")
    print(f"Average decryption time per file: {avg_time_per_file:.4f} seconds.")

    # 计算解密速率
    total_size = sum(os.path.getsize(os.path.join(decrypted_folder_path, f)) for f in os.listdir(decrypted_folder_path) if os.path.isfile(os.path.join(decrypted_folder_path, f)))
    decryption_rate = total_size / total_time_taken if total_time_taken > 0 else 0
    print(f"Decryption rate: {decryption_rate:.2f} bytes/second.")

if __name__ == "__main__":
    main() 
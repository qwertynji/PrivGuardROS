import os
import time
import socket as sk
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

# 发送文件到服务器  
def send_file_to_server(server_ip, server_port, file_path):
    FILE_NAME_END = b"\r\n\r\n" 
    try:
        file_size = os.path.getsize(file_path)
        sock = sk.socket(sk.AF_INET, sk.SOCK_STREAM)
        sock.connect((server_ip, server_port))
        with open(file_path, 'rb') as f:
            file_name = os.path.basename(file_path)
            file_name_bytes = file_name.encode('utf-8')
            sock.sendall(file_name_bytes + FILE_NAME_END) # 发送文件名和分隔符
            sock.sendfile(f) # 发送文件内容
        print('File uploaded successfully')
        return file_size
    except Exception as e:
        print(f'File upload failed: {str(e)}')
        return 0
    finally:
        sock.close()

def upload_all_files_in_directory(directory_path, server_ip, server_port):
    total_file_size = 0
    total_time_spent = 0
    files_uploaded = 0
    file_counter = 0

    for file_name in os.listdir(directory_path):
        file_path = os.path.join(directory_path, file_name)
        # 确认是否是文件
        if os.path.isfile(file_path): 
            file_counter += 1 # 更新文件计数器
            print(f"Uploading the {file_counter} file: {file_name}")
            start_time = time.time()
            file_size = send_file_to_server(server_ip, server_port, file_path)
            end_time = time.time()
            total_file_size += file_size
            total_time_spent += end_time - start_time
            files_uploaded += 1 if file_size > 0 else 0

    return total_file_size, total_time_spent, files_uploaded

def main():
    dir_path = 'W:\imagedata_2'
    encrypted_dir_path = os.path.join(dir_path, "encrypted")
    
    if not os.path.exists(encrypted_dir_path):
        os.makedirs(encrypted_dir_path)
    total_files_uploaded = 0

    server_ip = '8.138.56.15'
    server_port = 5000
    total_file_size, total_time_spent, files_uploaded = upload_all_files_in_directory(encrypted_dir_path, server_ip, server_port)
    total_files_uploaded += files_uploaded

    print(f"Total data size: {total_file_size} bytes")
    print(f"Average image size: {total_file_size/10000} bytes")
    print(f"Total upload time: {total_time_spent} seconds")
    print(f"Total upload rate: {total_file_size / 1024 / 1024 / total_time_spent} mb/s")
    print(f"Total number of uploaded files: {total_files_uploaded}")

if __name__ == "__main__":
    main()  




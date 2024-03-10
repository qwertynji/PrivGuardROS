import socket
import os
import pika
import uuid
import requests
import re

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

server_ip = '0.0.0.0'
server_port = 5000
save_directory = '/root' 
rabbitmq_host = '8.138.56.15'
queue_name = 'file_upload_queue'  
producer = Producer(rabbitmq_host, queue_name) 
FILE_NAME_END = b"\r\n\r\n"

def receive_and_publish_file():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.bind((server_ip, server_port))
        sock.listen(1) 
        print('Waiting for the file to upload...')
        while True:
            connection, address = sock.accept()
            received_data = b""
            while True:
                part = connection.recv(1024)
                received_data += part
                if FILE_NAME_END in received_data:
                    break
            file_name_bytes, _, remaining_data = received_data.partition(FILE_NAME_END)
            file_name = file_name_bytes.decode('utf-8')
            print(f'Received file names:{file_name}')
            # 使用正则表达式从文件名中提取数字作为ID
            match = re.search(r'\d+', file_name)
            file_id = match.group(0) if match else None
            if file_id is None:
                print('The ID cannot be extracted because no number is found in the file name')
                continue
            save_path = os.path.join(save_directory, file_name)
            with open(save_path, 'wb') as f:
                while True:
                    data = connection.recv(1024)
                    if not data:
                        break
                    f.write(data)
            print(f'File {file_name} received successfully')
            connection.close()
            with open(save_path, 'rb') as file:
                files = {'file': file}
                response = requests.post(f'http://172.17.178.56:5001/api/v0/add', files=files)
                if response.status_code == 200:
                    response_json = response.json()
                    cid = response_json['Hash']
                    print(f'IPFS CID: {cid}')
                    message = f"ID: {file_id} - CID: {cid}"
                    producer.call(message)
                    print(f'Mapping relationship {message} uploaded successfully!')
                else:
                    print('Failed to upload the file.')
    except Exception as e:
        print(f'File receiving failure: {str(e)}')
    finally:
        sock.close()

receive_and_publish_file()
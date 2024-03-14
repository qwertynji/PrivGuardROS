import pika
import uuid
import time

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

output_file = r'W:\rabbitMQ_test\messages_stats.txt'

def receive_and_publish_file(num_messages):
    try:
        start_time = time.time() # 开始计时
        for i in range(num_messages):
            hash = "05334acfd71742a48ec9726cc5c05a03c248f295c010e493810fd92ada723d47"
            producer.call(hash.encode()) # 发送 hash
        end_time = time.time() # 结束计时
        duration = end_time - start_time # 发送指定数量消息所需的时间
        print(f'Time required to send {num_messages} messages: {duration} seconds.')
        print(f'Send rate: {num_messages/duration} bars/second.')
        with open(output_file, 'w') as file:
            file.write(f'Time required to send {num_messages} messages: {duration} seconds.\n')
            file.write(f'Send rate: {num_messages/duration} bars/second.\n')
    except Exception as e:
        print(f'Error: {str(e)}.')

receive_and_publish_file(10000)
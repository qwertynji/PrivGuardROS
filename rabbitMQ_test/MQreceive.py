import pika
import time
import threading

# RabbitMQ 服务器和端口配置
rabbitmq_host = '8.138.56.15'
rabbitmq_port = 5672
connection_parameters = pika.ConnectionParameters(host=rabbitmq_host, port=rabbitmq_port)

output_dir = r'W:\rabbitMQ_test' # 保存文件的目录

# 全局变量记录接收到的总数量及开始时间
global_count = {'value': 0}
start_time = time.time()
lock = threading.Lock()

# 创建一个事件，当全局计数到达目标值时设置
shutdown_event = threading.Event()

def consumer_callback(ch, method, properties, body, consumer_id, counts, shutdown_event):
    message = body.decode('utf-8')
    print(f"Consumer {consumer_id} received message: {message}")
    with lock:
        counts['global'] += 1
        counts[consumer_id] += 1
        if counts['global'] >= 10000:
            shutdown_event.set()
    # 确认信息
    ch.basic_ack(delivery_tag=method.delivery_tag)
    if shutdown_event.is_set():
        ch.stop_consuming()

# 在单独的线程中启动消费者
def start_consumer(consumer_id, counts, shutdown_event):
    # 与RabbitMQ建立连接
    connection = pika.BlockingConnection(connection_parameters)
    channel = connection.channel()
    queue_name = 'file_upload_queue'
    channel.queue_declare(queue=queue_name)
    channel.basic_consume(queue=queue_name, on_message_callback=lambda ch, method, properties, body: consumer_callback(ch, method, properties, body, consumer_id, counts, shutdown_event))
    
    while not shutdown_event.is_set():
        channel.connection.process_data_events(time_limit=1)
    
    channel.stop_consuming()
    # 完成消费后关闭连接
    connection.close()

    time_elapsed = time.time() - start_time
    with open(f'{output_dir}/consumer_{consumer_id}_info.txt', 'w') as file:
        file.write(f"Total messages received by Consumer {consumer_id}: {counts[consumer_id]} in {time_elapsed} seconds.\n")

counts = {'global': 0, 'consumer1': 0, 'consumer2': 0, 'consumer3': 0}

threads = []
for i in range(1, 4):
    consumer_id = f'consumer{i}'
    thread = threading.Thread(target=start_consumer, args=(consumer_id, counts, shutdown_event))
    thread.start()
    threads.append(thread)

# 等待所有线程完成
for thread in threads:
    thread.join()

# 计算和记录总体统计信息
total_time_elapsed = time.time() - start_time
total_messages_received = counts['global']
with open(f'{output_dir}/overall_info.txt', 'w') as file:
    file.write(f"Total messages received: {total_messages_received} in {total_time_elapsed} seconds.\n")
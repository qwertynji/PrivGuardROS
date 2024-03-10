# -*- 需要运行在py3的环境中 -*-
import time
import sys
import os
from File_oper import File
from pack.BasePacker import BasePacker
from SM.sm2 import SM2
from socket import *
curPath = os.path.abspath(os.path.dirname('register.py'))
rootPath = os.path.split(curPath)[0]
sys.path.append(rootPath)

#tcp/ip连接目标IP/port
ip = '8.134.222.175'
port = 5500
tcp_cli = socket(AF_INET,SOCK_STREAM)
#SM2加密算法实例化
sm2 = SM2()

if __name__ == '__main__':

    print ("Welcome to ROS-Ethereum !")
    time.sleep(1)
    #创建TCP/IP连接
    try:
        tcp_cli.connect((ip,port))
    except Exception:
        print ('Time out or unknow IP')
        exit(1)

    print ('-------------Warning---------------\n' \
           'The name you enter is important, please keep that for future using!.\n')
    User_name = input('Please input your username. \n')
    Passwd = input('Please input your password. \n')
    #输入用于信息传输加密的对称sm4密钥
    sm4_key = input("For the first use, please input your sm4 key for encryption. \n")
    #sm2公钥
    DB = (22268492674489632100475815153735255059814905571291708705868265302433421784436, 267259724495297109348381784928615944362750090458611683013613014465783061313)
    #将sm4密钥使用sm2公钥加密
    sm4_enc = sm2.encrypt(str(sm4_key),DB)
    #传输注册指令
    while BasePacker.command_send('register',cli=tcp_cli,username=User_name,sm4_enc=sm4_enc,passwd=Passwd):
        User_name = input('Please choose your username again. \n')
    #向对应Text文件中写入用户名/sm4密钥以及密码
    name = File('./deploy_args/Username.txt')
    key_file = File('./deploy_args/keys.txt')
    passwd_file = File('./deploy_args/passwd.txt')
    name.write_txt(User_name)
    key_file.write_txt(sm4_key)
    passwd_file.write_txt(Passwd)
    #释放连接
    tcp_cli.close()




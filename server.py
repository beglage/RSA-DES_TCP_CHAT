import rsa
import socket
import threading
import pickle
import sys
import pyDes
import time

Des_Key = b'qwerasdf'
Des_IV = b"\x00\x00\x00\x00\x00\x00\x00\x00"
PORT = 4396
BUFF = 1024
def DesEncrypt(str):
    k=pyDes.des(Des_Key,pyDes.CBC,Des_IV,pad=None,padmode=pyDes.PAD_PKCS5)
    Encrypt_Str = k.encrypt(str)
    return Encrypt_Str
def DesDecrypt(str):
    k = pyDes.des(Des_Key, pyDes.CBC, Des_IV, pad = None, padmode = pyDes.PAD_PKCS5)
    Decrypt_Str = k.decrypt(str)
    return Decrypt_Str
def SendMessage(Sock, test):
    while True:
        SendData = input("")
        if SendData == "exit":
                Sock.close()
        encryptdata = DesEncrypt(SendData)
        print('加密数据:(' + str(encryptdata)+')')
        if len(SendData) > 0:
            Sock.send(encryptdata)
def RecvMessage(Sock, test):
    while True:
        Message = Sock.recv(BUFF)
        decryptdata = DesDecrypt(Message)
        if len(Message)>0:
            print("接收到消息:" + decryptdata.decode('utf8'))


#接收RSA公钥
def RecvRsaPub(Sock):
    Message = Sock.recv(BUFF)
    PubKey = pickle.loads(Message)
    return PubKey

#发送DES密钥
def SendDesKey(Sock, PubKey):
    content = Des_Key
    Encrypt_Str = rsa.encrypt(content, PubKey)
    Message = pickle.dumps([Encrypt_Str,Des_IV])
    Sock.send(Message)
    return 1

                
def main():
    ServerSock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    ServerSock.bind(('127.0.0.1',PORT))
    ServerSock.listen(5)
    print("listening........")
    while True:
        ConSock,addr = ServerSock.accept()
        print('connection succeed' + '\n' + 'you can chat online')
        print("正在接收RSA公钥........")
        time.sleep(1)
        PubKey = RecvRsaPub(ConSock)
        print("成功接收RSA公钥")
        #print(PubKey)
        if PubKey:
            print("正在发送DES密钥........")
            e = SendDesKey(ConSock, PubKey)
            time.sleep(1)
            print("成功发送DES密钥")
            print("---------加密会话----------")
            if e:
                thread_1 = threading.Thread(target = SendMessage, args = (ConSock, None))
                thread_2 = threading.Thread(target = RecvMessage, args = (ConSock, None))
                thread_1.start()
                thread_2.start()

if __name__ == '__main__':
    main()

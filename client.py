import rsa
import socket
import threading
import pickle
import sys
import pyDes
import time

#Des_Key = b'qwerasdf'
#Des_IV = b"\x00\x00\x00\x00\x00\x00\x00\x00"
PORT = 4396
BUFF = 1024
def DesEncrypt(str, Des_Key, Des_IV):
    k=pyDes.des(Des_Key,pyDes.CBC,Des_IV,pad=None,padmode=pyDes.PAD_PKCS5)
    Encrypt_Str = k.encrypt(str)
    return Encrypt_Str
def DesDecrypt(str, Des_Key, Des_IV):
    k = pyDes.des(Des_Key, pyDes.CBC, Des_IV, pad = None, padmode = pyDes.PAD_PKCS5)
    Decrypt_Str = k.decrypt(str)
    return Decrypt_Str
def SendMessage(Sock, Des_Key, Des_IV):
    try:
        while True:
            SendData = input("")
            if SendData == "exit":
                Sock.close()
            encryptdata = DesEncrypt(SendData, Des_Key, Des_IV)
            print('加密数据:(' + str(encryptdata)+')')
            if len(SendData) > 0:
                Sock.send(encryptdata)
    except:
        return 
    else:
        return 

def RecvMessage(Sock, Des_Key, Des_IV):
    while True:
        Message = Sock.recv(BUFF)
        decryptdata = DesDecrypt(Message, Des_Key, Des_IV)
        if len(Message)>0:
            print("接收到消息:" + decryptdata.decode('utf8'))



#RSA公私钥生成
def rsaCreate():
    (PubKey, PrivateKey) = rsa.newkeys(512)
    return (PubKey, PrivateKey)

#发送公钥
def SendRSAPub(Sock, PubKey):
    #print(Pb)
    data = pickle.dumps(PubKey) 
    Sock.send(data)
    return 1

def RsaDecrypt(str, PrivateKey):
    Decrypt_Str = rsa.decrypt(str, PrivateKey)
    Decrypt_Str_1 = Decrypt_Str.decode('utf8')
    return Decrypt_Str_1

#接收Des密钥
def RecvDesKey(Sock, PrivateKey):
    Message = Sock.recv(BUFF)
    #print(Des_Key)
    (enDesKey,Des_IV) = pickle.loads(Message)
    Des_Key = RsaDecrypt(enDesKey, PrivateKey)
    Des_Key = Des_Key.encode('utf-8')
    return (Des_Key,Des_IV)


def main():
    ClientSock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ServerAddr = "127.0.0.1"
    #input("please input the server's ip address:")
    ClientSock.connect((ServerAddr, PORT))
    print('connection succeed, chat start!')
    (PubKey, PrivateKey) = rsaCreate()
    print("正在发送RSA公钥........")
    k = SendRSAPub(ClientSock, PubKey)
    time.sleep(1)
    print("成功发送RSA公钥")
    if k:
        print("正在接收DES密钥........")
        time.sleep(1)
        (Des_Key,Des_IV) = RecvDesKey(ClientSock, PrivateKey)
        print("成功接收DES密钥")
        #print(Des_Key,Des_IV)
        print("---------加密会话----------")
        if Des_Key:
            thread_3 = threading.Thread(target = SendMessage, args = (ClientSock, Des_Key, Des_IV))
            thread_4 = threading.Thread(target = RecvMessage, args = (ClientSock, Des_Key, Des_IV))
            thread_3.start()
            thread_4.start()

if __name__ == '__main__':
    main()

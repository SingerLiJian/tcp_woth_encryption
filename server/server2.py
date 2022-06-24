import socket
import threading
from tkinter import *
from Crypto import Random
from Crypto.Cipher import PKCS1_v1_5 as PKCS1_cipher
from Crypto.PublicKey import RSA
from tkinter import scrolledtext
from Crypto.Hash import SHA
import base64
import random
from Crypto.Signature import PKCS1_v1_5 as PKCS1_signature
from Crypto.Cipher import AES
from binascii import b2a_hex, a2b_hex

def create_aeskey():
    seed = "1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!@#$%^&*()_+=-"
    sa = []
    for i in range(16):
        sa.append(random.choice(seed))
    key = ''.join(sa)
    return key

def design(mes,signature):
    with open('C:/Users/11561/Desktop/python/东西/internet security/CA/client_public_key.rsa') as f:
        key = f.read()
        pub_key = RSA.importKey(key)
        verifier = PKCS1_signature.new(pub_key)
        digest = SHA.new()
        digest.update(mes.encode("gbk"))
        return verifier.verify(digest, base64.b64decode(signature))

def ensign(mes):
    with open('C:/Users/11561/Desktop/python/东西/internet security/server/server_private_key.rsa') as f:
        key = f.read()
        pri_key = RSA.importKey(key)
        signer = PKCS1_signature.new(pri_key)
        digest = SHA.new()
        digest.update(mes.encode("gbk"))
        sign = signer.sign(digest)
        signature = base64.b64encode(sign)
        return signature

def create_key():
    random_generator = Random.new().read
    rsa = RSA.generate(2048,random_generator)
    private_key = rsa.exportKey()
    with open('C:/Users/11561/Desktop/python/东西/internet security/server/server_private_key.rsa','wb') as f:
        f.write(private_key)
        f.close()
    public_key = rsa.publickey().exportKey()
    with open('C:/Users/11561/Desktop/python/东西/internet security/CA/server_public_key.rsa','wb') as f:
        f.write(public_key)
        f.close()

def aes_encrypt(mes,key):
    mode = AES.MODE_OFB
    cryptor = AES.new(key.encode('gbk'), mode, b'0000000000000000')
    length = 16
    count = len(mes)
    if count%length != 0:
        add = length - (count % length)
    else:
        add = 0
    message = mes + ('\0' * add)
    ciphertext = cryptor.encrypt(message.encode('gbk'))
    result = b2a_hex(ciphertext)
    return result


def aes_decrypt(result,key):
    mode = AES.MODE_OFB
    cryptor = AES.new(key.encode('gbk'), mode, b'0000000000000000')
    plain_text = cryptor.decrypt(a2b_hex(result))
    return plain_text.decode('gbk').rstrip('\0')

def rsa_decrypt(secret_aes_key):
    with open('C:/Users/11561/Desktop/python/东西/internet security/server/server_private_key.rsa') as f:
        key = f.read()
        pri_key = RSA.importKey(key)
        cipher = PKCS1_cipher.new(pri_key)
        back_text = cipher.decrypt(base64.b64decode(secret_aes_key), 0)
        return back_text.decode('gbk')

def rsa_encryp(mes):
    with open('C:/Users/11561/Desktop/python/东西/internet security/CA/client_public_key.rsa') as f:
        key = f.read()
        pub_key = RSA.importKey(str(key))
        cipher = PKCS1_cipher.new(pub_key)
        rsa_text = base64.b64encode(cipher.encrypt(bytes(mes.encode("gbk"))))
        return rsa_text

def server():
    tcp_server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp_server_socket.bind(("", 1314))
    tcp_server_socket.listen(5)
    while True:
        new_client_socket, client_addr = tcp_server_socket.accept()
        select = new_client_socket.recv(1).decode("gbk")
        if select == '1':
            recv_mes(new_client_socket, client_addr)
        elif select == '2':
            recv_file(new_client_socket, client_addr)
        elif select == '3':
            send_file_to_client(new_client_socket,client_addr)
        else:
            pass
        new_client_socket.close()


def recv_mes(new_client_socket, client_addr):
    mes_content = new_client_socket.recv(1024*1024).decode("gbk")
    print(mes_content)
    summes=mes_content.split("<delim>")
    secret_aes_key=summes[1].encode("gbk")[2:-1]
    print(secret_aes_key)
    aes_key=rsa_decrypt(secret_aes_key)
    print(aes_key)
    mes_aes=summes[0].encode("gbk")[2:-1]
    print(mes_aes)
    mes=aes_decrypt(mes_aes,aes_key).split("<delim>")
    dest_content=mes[0]
    ver =design(dest_content,mes[1].encode("gbk")[2:-1])
    if ver==True:
        l1.insert(END, "%s用户发来的消息是:%s\n"% (client_addr,dest_content))
        if mes_content =="":
            new_client_socket.send("填写发送内容不能为空！".encode("gbk"))
        else:
            new_client_socket.send("已收到你所发的内容！".encode("gbk"))


def recv_file(new_client_socket, client_addr):
    recv_data = new_client_socket.recv(1024 * 1024 * 1024).decode("gbk")
    print(recv_data)
    summes = recv_data.split("<delim>")
    secret_aes_key = summes[1].encode("gbk")[2:-1]
    print(secret_aes_key)
    aes_key = rsa_decrypt(secret_aes_key)
    print(aes_key)
    mes_aes = summes[0].encode("gbk")[2:-1]
    print(mes_aes)
    mes = aes_decrypt(mes_aes, aes_key).split("<delim>")
    dest_content = mes[0]
    ver = design(dest_content, mes[1].encode("gbk")[2:-1])
    if ver == True:
            with open("[new]"+ str(client_addr)+".txt", "w")as f:
                f.write(dest_content)
                f.close()
            l1.insert(END,"成功接收文件,请查收\n")
    else:
        l1.insert(END, "接收文件来自:%s失败\n" % str(client_addr))

def send_file_to_client(new_client_socket,client_addr):
    file_name = new_client_socket.recv(1024*1024).decode("gbk")
    l1.insert(END,"(%s)用户需要下载文件:%s\n"% (str(client_addr),file_name))
    file_content = None
    try:
        f = open(file_name,"r",encoding="utf-8")
        file_content = f.read()
        f.close()
    except Exception as ret:
        l1.insert(END, "没有需要下载的文件（%s）\n"%file_name)
        new_client_socket.send("没有你要的文件".encode("gbk"))
    if file_content:
        aes_key = create_aeskey()
        print(aes_key)
        secret_aes_key = rsa_encryp(aes_key)
        print(secret_aes_key)
        sign_content = ensign(file_content)
        print(sign_content)
        mes = file_content + '<delim>' + str(sign_content)
        print(mes)
        mes_aes = aes_encrypt(mes, aes_key)
        print(mes_aes)
        summes = str(mes_aes) + '<delim>' + str(secret_aes_key)
        print(summes)
        new_client_socket.send(summes.encode("gbk"))
        l1.insert(END, "已发送%s用户需要的文件%s\n"%(str(client_addr),file_name) )


create_key()
top = Tk()
top.title('服务器')
top.geometry('500x390+500+200')
l2 = Label(top, text="消息框", font=("幼圆", 30)).place(x=180, y=320)
top.resizable(False, False)
l1 = scrolledtext.ScrolledText(top , width=56, height=20)
l1.place(x=50, y=30)
threading.Thread(target=server).start()
top.mainloop()



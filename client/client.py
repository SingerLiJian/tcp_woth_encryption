import socket
from tkinter import *
from tkinter import messagebox
from Crypto import Random
from Crypto.Cipher import PKCS1_v1_5 as PKCS1_cipher
from Crypto.PublicKey import RSA
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


def create_key():
    random_generator = Random.new().read
    rsa = RSA.generate(2048,random_generator)
    private_key = rsa.exportKey()
    with open('C:/Users/11561/Desktop/python/东西/internet security/client/client_private_key.rsa','wb') as f:
        f.write(private_key)
        f.close()
    public_key = rsa.publickey().exportKey()
    with open('C:/Users/11561/Desktop/python/东西/internet security/CA/client_public_key.rsa','wb') as f:
        f.write(public_key)
        f.close()

def design(mes,signature):
    with open('C:/Users/11561/Desktop/python/东西/internet security/CA/server_public_key.rsa') as f:
        key = f.read()
        pub_key = RSA.importKey(key)
        verifier = PKCS1_signature.new(pub_key)
        digest = SHA.new()
        digest.update(mes.encode("gbk"))
        return verifier.verify(digest, base64.b64decode(signature))

def ensign(mes):
    with open('C:/Users/11561/Desktop/python/东西/internet security/client/client_private_key.rsa') as f:
        key = f.read()
        pri_key = RSA.importKey(key)
        signer = PKCS1_signature.new(pri_key)
        digest = SHA.new()
        digest.update(mes.encode("gbk"))
        sign = signer.sign(digest)
        signature = base64.b64encode(sign)
        return signature

def rsa_decrypt(secret_aes_key):
    with open('C:/Users/11561/Desktop/python/东西/internet security/client/client_private_key.rsa') as f:
        key = f.read()
        pri_key = RSA.importKey(key)
        cipher = PKCS1_cipher.new(pri_key)
        back_text = cipher.decrypt(base64.b64decode(secret_aes_key), 0)
        return back_text.decode('gbk')

def rsa_encryp(mes):
    with open('C:/Users/11561/Desktop/python/东西/internet security/CA/server_public_key.rsa') as f:
        key = f.read()
        pub_key = RSA.importKey(str(key))
        cipher = PKCS1_cipher.new(pub_key)
        rsa_text = base64.b64encode(cipher.encrypt(bytes(mes.encode("gbk"))))
        return rsa_text

def aes_decrypt(result,key):
    mode = AES.MODE_OFB
    cryptor = AES.new(key.encode('gbk'), mode, b'0000000000000000')
    plain_text = cryptor.decrypt(a2b_hex(result))
    return plain_text.decode('gbk').rstrip('\0')

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


def client(dest_ip,dest_port,dest_name,select):
    tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp_socket.connect((dest_ip, int(dest_port)))
    if select == '1':
        tcp_socket.send(select.encode("gbk"))
        send_mes(tcp_socket,dest_name)
    elif select == '2':
        tcp_socket.send(select.encode("gbk"))
        send_file(tcp_socket,dest_name)
    elif select == '3':
        tcp_socket.send(select.encode("gbk"))
        get_file(tcp_socket,dest_name)
    else:
        messagebox.showinfo(title='提示', message="请选择选项")
    tcp_socket.close()

def get_file(tcp_socket,download_file_name):
    tcp_socket.send(download_file_name.encode("gbk"))
    recv_data = tcp_socket.recv(1024 * 1024*1024).decode("gbk")
    if recv_data=="没有你要的文件":
        messagebox.showinfo(title='提示', message="没有你要的文件")
    elif recv_data:
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
            with open("[new]" +download_file_name, "w")as f:
                f.write(dest_content)
                f.close()
            messagebox.showinfo(title='提示', message="成功接收文件")
        else:
            messagebox.showinfo(title='提示', message="接收文件失败")


def send_file(tcp_socket,file_name):
    file_content=None
    try:
        f = open(file_name, "r",encoding="utf-8")
        file_content = f.read()
        f.close()
    except Exception as ret:
        messagebox.showinfo(title='提示', message="没有要发送的文件")
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
        tcp_socket.send(summes.encode("gbk"))
        messagebox.showinfo(title='提示', message="已发送文件%s"% file_name)

def send_mes(tcp_socket,dest_content):
    aes_key=create_aeskey()
    print(aes_key)
    secret_aes_key=rsa_encryp(aes_key)
    print(secret_aes_key)
    sign_content = ensign(dest_content)
    print(sign_content)
    mes=dest_content+'<delim>'+str(sign_content)
    print(mes)
    mes_aes=aes_encrypt(mes,aes_key)
    print(mes_aes)
    summes= str(mes_aes)+'<delim>'+str(secret_aes_key)
    print(summes)
    tcp_socket.send(summes.encode("gbk"))
    recv_data = tcp_socket.recv(1024)
    messagebox.showinfo(title='提示', message=str(recv_data.decode("gbk")))


def main():
    create_key()
    top = Tk()
    top.title("客户端")
    top.geometry('500x340+500+200')
    top.resizable(False, False)
    l1 = Label(top, text="ip：", font=("楷体", 20)).place(x=20, y=50)
    l2 = Label(top, text="port：", font=("楷体", 20)).place(x=20, y=110)
    l3 = Label(top, text="name：", font=("楷体", 20)).place(x=20, y=170)
    a = StringVar(value="<请输入下载服务器的ip>")
    b = StringVar(value="<请输入下载服务器的port>")
    c = StringVar(value="<请输入消息或文件名>")
    i1 = Entry(top, textvariable=a).place(x=100, y=50, width=370,height=30)
    i2 = Entry(top, textvariable=b).place(x=100, y=110, width=370, height=30)
    i2 = Entry(top, textvariable=c).place(x=100, y=170, width=370, height=30)
    select = StringVar()
    select.set('4')
    s1 = Radiobutton(top, text='发消息', fg='red', variable=select, value='1').place(x=63, y=220)
    s2 = Radiobutton(top, text='发文件', fg='blue', variable=select, value='2').place(x=229, y=220)
    s3 = Radiobutton(top, text='收文件', fg='green', variable=select, value='3').place(x=396, y=220)
    l7 = Button(top, text="提交", font=("幼圆", 20), command=lambda: client(a.get(), b.get(),c.get(),select.get())).place(x=200, y=260,width=100)

    top.mainloop()

if __name__ == '__main__':
        main()
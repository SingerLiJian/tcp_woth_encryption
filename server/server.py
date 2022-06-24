import socket
import threading
from tkinter import *
from tkinter import messagebox
from tkinter import ttk

def text_input(content):
    gui().l1.insert

def gui():
    top = Tk()
    top.title('服务器')
    top.geometry('800x800+500+200')
    top.resizable(False, False)
    l1 = Text(top).place(x=100, y=50, width=370, height=30)
    top.mainloop()


def server(tcp_server_socket):
    while True:
        new_client_socket, client_addr = tcp_server_socket.accept()
        select = new_client_socket.recv(1024).decode("gbk")
        if select == '1':
            recv_mes(new_client_socket, client_addr)
        elif select == '2':
            recv_file(new_client_socket, client_addr)
        elif select == '3':
            send_file_to_client(new_client_socket, client_addr)
        else:
            pass
        new_client_socket.close()


def recv_mes():
    pass

def recv_file():
    pass

def send_file_to_client(new_client_socket,client_addr):
    file_name = new_client_socket.recv(1024*1024).decode("gbk")
    text_input("客户端（%s）需要下载的文件是:%s"%(str(client_addr),file_name))
    file_content = None
    try:
        f = open(file_name,"rb")
        file_content = f.read()
        f.close()
    except Exception as ret:
        print("没有需要下载的文件（%s）"%file_name)
    if file_content:
        new_client_socket.send(file_content)


def main():
    tcp_server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp_server_socket.bind(("", 1314))
    tcp_server_socket.listen(5)

    threads = []
    t1 = threading.Thread(target=gui)
    threads.append(t1)
    t2 = threading.Thread(target=server, args=(tcp_server_socket,))
    threads.append(t2)
    for t in threads:
        t.start()
    for t in threads:
        t.join()


if __name__ == '__main__':
    main()
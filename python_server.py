import socket
import datetime

HOST = 'localhost'
PORT = 1540

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((HOST, PORT))
    s.listen(1)
    conn, addr = s.accept()
    with conn:
        print(f"Server: Connected by {addr}")
        while True:
            conn.sendall(f"Hello !\nTime is {datetime.datetime.now()}\n".encode())

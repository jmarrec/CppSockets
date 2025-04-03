import socket
import time

HOST = 'localhost'
PORT = 1540

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))
    print(f"Client: Connection to {HOST}:{PORT} succeeded")

    # s.setblocking(False)
    s.settimeout(1.0)

    last_time = time.time()

    while True:
        t = time.time()
        if (t - last_time) > 2:
            print("+---> PING")
            s.send('PING'.encode())
            last_time = t
            time.sleep(1)

        try:
            data = s.recv(1024)
            if not data:
                break
            print(data.decode(), end="")
        except TimeoutError:
            print("")
            pass


print("Client: Goodbye")

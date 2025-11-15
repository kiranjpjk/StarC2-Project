# import socket
# import threading

# LISTEN_PORT = 4444

# sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# sock.bind(("0.0.0.0", LISTEN_PORT))
# sock.listen(1)

# print(f"[Linux] Listening on port {LISTEN_PORT}...")
# client, addr = sock.accept()

# print(f"[+] Connected by Windows agent: {addr}")

# def receive():
#     while True:
#         try:
#             data = client.recv(4096)
#             if not data:
#                 break
#             print("\n[Windows] " + data.decode())
#         except:
#             break

# threading.Thread(target=receive, daemon=True).start()

# while True:
#     msg = input("Linux> ")
#     client.send(msg.encode())

# linux_chat_server.py
import socket

HOST = "0.0.0.0"
PORT = 6000

s = socket.socket()
s.bind((HOST, PORT))
s.listen(1)

print("Waiting for Windows connection...")
client, addr = s.accept()
print("Connected to:", addr)

while True:
    msg = client.recv(1024).decode()
    if msg:
        print("Windows:", msg)
    reply = input("Linux: ")
    client.send(reply.encode())
//

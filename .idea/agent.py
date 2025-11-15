# import socket
# import threading
# import time

# LINUX_IP = input("Enter Linux public IP: ").strip()
# LINUX_PORT = 4444

# while True:
#     try:
#         print(f"[Windows] Trying to connect to {LINUX_IP}:{LINUX_PORT}...")
#         sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#         sock.connect((LINUX_IP, LINUX_PORT))
#         print("[+] Connected to Linux!")

#         def receive():
#             while True:
#                 try:
#                     data = sock.recv(4096)
#                     if not data:
#                         break
#                     print("\n[Linux] " + data.decode())
#                 except:
#                     break

#         threading.Thread(target=receive, daemon=True).start()

#         while True:
#             msg = input("Windows> ")
#             sock.send(msg.encode())

# # windows_chat_client.py
# import socket

# LINUX_IP = "100.xx.xx.xx"
# PORT = 6000

# s = socket.socket()
# s.connect((LINUX_IP, PORT))

# while True:
#     message = input("Windows: ")
#     s.send(message.encode())
    
#     reply = s.recv(1024).decode()
#     print("Linux:", reply)


#     except Exception as e:
#         print(f"Connection failed: {e}")
#         print("Retrying in 5 seconds...")
#         time.sleep(5)
import socket
import select

HOST = '0.0.0.0'
PORT = 5000

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind((HOST, PORT))
server.listen(5)
print(f"[+] Relay Server Running on port {PORT}")

sockets = [server]
clients = {}

while True:
    readable, _, _ = select.select(sockets, [], [])

    for sock in readable:
        # New client connected
        if sock is server:
            conn, addr = server.accept()
            sockets.append(conn)
            clients[conn] = addr
            print(f"[+] Client connected: {addr}")

        # Existing client sends data
        else:
            data = sock.recv(1024)
            if not data:
                print(f"[-] Client disconnected: {clients[sock]}")
                sockets.remove(sock)
                del clients[sock]
                sock.close()
                continue

            print(f"[Relay] From {clients[sock]}: {data.decode()}")

            # Relay to all other connected clients
            for c in list(clients.keys()):
                if c != sock:
                    try:
                        c.send(data)
                    except:
                        pass
//
//
//
import socket
import threading

SERVER_IP = "YOUR_RELAY_SERVER_IP"
SERVER_PORT = 5000

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect((SERVER_IP, SERVER_PORT))

print("[+] Connected to Relay Server")

def receive():
    while True:
        try:
            msg = sock.recv(1024).decode()
            if msg:
                print("\n[Message] ", msg)
        except:
            break

threading.Thread(target=receive, daemon=True).start()

while True:
    msg = input()
    sock.send(msg.encode())


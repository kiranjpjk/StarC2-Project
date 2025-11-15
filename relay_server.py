import socket
import threading

SERVER_IP = "0.0.0.0"   # Listen on all interfaces
SERVER_PORT = 5000

clients = []  # List to store connected clients

def handle_client(client_socket, client_address):
    print(f"[+] {client_address} connected")
    while True:
        try:
            msg = client_socket.recv(1024)
            if not msg:
                break

            # Broadcast message to all other clients
            for c in clients:
                if c != client_socket:
                    c.send(msg)

        except:
            break

    print(f"[-] {client_address} disconnected")
    clients.remove(client_socket)
    client_socket.close()


sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.bind((SERVER_IP, SERVER_PORT))
sock.listen(20)

print(f"[Relay] Running on {SERVER_IP}:{SERVER_PORT}")

while True:
    client_socket, client_address = sock.accept()
    clients.append(client_socket)

    t = threading.Thread(target=handle_client, args=(client_socket, client_address))
    t.daemon = True
    t.start()

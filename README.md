# StarC2-Project
This is my Final year project
import socket

UDP_IP = "192.168.1.20"  # Windows machine IP
UDP_PORT = 5005
MESSAGE = "Hello from Linux!"

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.sendto(MESSAGE.encode(), (UDP_IP, UDP_PORT))
print("Message sent!")

sudo apt install netcat -y
echo "Hi from Linux" | nc -u 192.168.1.20 5005

//
import socket

# Server (Windows) side
LISTEN_IP = "0.0.0.0"
LISTEN_PORT = 5005

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((LISTEN_IP, LISTEN_PORT))

print(f"[Windows] Listening on UDP port {LISTEN_PORT}...")

while True:
    data, addr = sock.recvfrom(1024)
    message = data.decode()
    print(f"Received from {addr}: {message}")

    # Reply back to sender (Linux)
    reply = input("Enter reply: ")
    sock.sendto(reply.encode(), addr)


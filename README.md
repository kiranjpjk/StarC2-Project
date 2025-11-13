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

import ssl
import socket

context = ssl.create_default_context()
context.check_hostname = False
context.verify_mode = ssl.CERT_NONE

hostname = "localhost"  # or IP of the server
conn = context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=hostname)

conn.connect((hostname, 4443))

# Simulated data
vehicle_data = "Location: (22.57, 88.36), Speed: 69 km/h"
conn.send(vehicle_data.encode())

response = conn.recv(1024)
print("Transmitted", response.decode())

conn.close()


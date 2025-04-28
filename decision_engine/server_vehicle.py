import ssl, socket
import time  # <-- Import the time module

context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
context.load_cert_chain(certfile="cert.pem", keyfile="key.pem")

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind(('localhost', 4443))
server_socket.listen(5)

print("[SERVER] Waiting for vehicles...")

while True:
    conn, addr = server_socket.accept()
    start_time = time.time()  # <-- Start timing

    ssl_conn = context.wrap_socket(conn, server_side=True)
    print(f"[CONNECTED] Vehicle at {addr}")

    try:
        data = ssl_conn.recv(1024).decode()
        print(f"[DATA RECEIVED] {data}")
    except Exception as e:
        print(f"[ERROR] {e}")
    finally:
        ssl_conn.close()

    end_time = time.time()  # <-- End timing
    duration = end_time - start_time
    print(f"[CONNECTION CLOSED] Duration: {duration:.2f} seconds\n")
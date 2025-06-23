import socket
import threading

HOST = '0.0.0.0'
PORT = 5001

RESPONSE = b"GRAZIEDARIOGRAZIEDARIOGRAZIEDP1=\r\n"

def handle_client(conn, addr):
    print(f"🔌 Connection from {addr}")
    try:
        while True:
            data = conn.recv(4096)
            if not data:
                break
            print(f"📨 Received: {data.decode(errors='ignore')}")
            conn.sendall(RESPONSE)
    except Exception as e:
        print(f"[❌] Error: {e}")
    finally:
        conn.close()
        print(f"❌ Disconnected {addr}")

def start_server():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen()
        print(f"🚀 Serving plain TCP on {HOST}:{PORT}")
        while True:
            conn, addr = s.accept()
            threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()

if __name__ == "__main__":
    start_server()

import socket
import threading
import json

HOST = '127.0.0.1'
PORT = 65432

clients = {}

def broadcast(packet, sender_socket):
    for client in list(clients.keys()):
        if client != sender_socket:
            try:
                client.send(packet)
            except:
                client.close()
                del clients[client]

def handle_client(client_socket):
    try:
        pubkey_data = client_socket.recv(4096).decode()
        clients[client_socket] = {
            'public_key': pubkey_data,
            'addr': client_socket.getpeername()
        }
        print(f"[SERVER] Public key from {clients[client_socket]['addr']}")

        def send_keys_update():
            keys = {str(info['addr']): info['public_key']
                    for c, info in clients.items()}
            packet = json.dumps({"keys_update": keys}).encode()
            for c in clients:
                c.send(packet)

        send_keys_update()

        while True:
            packet = client_socket.recv(16384)
            if not packet:
                break

            broadcast(packet, client_socket)

    except Exception as e:
        print("Error:", e)

    finally:
        print(f"[SERVER] Lost connection {clients[client_socket]['addr']}")
        client_socket.close()
        del clients[client_socket]
        send_keys_update()

def start_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((HOST, PORT))
    server.listen()

    print(f"Server running on {HOST}:{PORT}")

    while True:
        client_socket, addr = server.accept()
        print(f"[SERVER] New client {addr}")
        threading.Thread(target=handle_client, args=(client_socket,)).start()

if __name__ == "__main__":
    start_server()

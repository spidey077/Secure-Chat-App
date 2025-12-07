# client_qt.py
import sys
import socket
import threading
import json
import os
import time

from PySide6 import QtCore, QtGui, QtWidgets
from PySide6.QtCore import Signal, Slot

import pygame

from crypto_utils import (
    generate_keys, encrypt_message, decrypt_message,
    sign_message, verify_signature,
    serialize_public_key
)
from cryptography.hazmat.primitives import serialization

# network config
HOST = "127.0.0.1"
PORT = 65432

private_key, public_key = generate_keys()


# --- Small helper widget for a message bubble ---
class MessageBubble(QtWidgets.QWidget):
    def __init__(self, text: str, name: str = "", is_me: bool = False, parent=None):
        super().__init__(parent)
        self.is_me = is_me

        name_label = QtWidgets.QLabel(name) if name else None
        text_label = QtWidgets.QLabel(text)
        text_label.setWordWrap(True)
        text_label.setTextInteractionFlags(QtCore.Qt.TextSelectableByMouse)

        # styling
        text_label.setStyleSheet("""
            QLabel {
                padding: 8px 12px;
                border-radius: 12px;
                font-family: Helvetica, Arial, sans-serif;
                font-size: 13px;
            }
        """)

        layout_v = QtWidgets.QVBoxLayout()
        layout_v.setContentsMargins(0, 0, 0, 0)
        layout_v.setSpacing(4)

        if name_label:
            name_label.setStyleSheet("QLabel { font-size: 10px; color: #cfd8dc; font-weight: 600; }")
            layout_v.addWidget(name_label, 0, QtCore.Qt.AlignLeft)

        layout_v.addWidget(text_label)

        container = QtWidgets.QFrame()
        container.setLayout(layout_v)

        # Bubble background color
        if is_me:
            container.setStyleSheet("QFrame { background: #25D366; border-radius: 12px; }")
            text_label.setStyleSheet(text_label.styleSheet() + " QLabel { color: #01281a; }")
        else:
            container.setStyleSheet("QFrame { background: #233238; border-radius: 12px; }")
            text_label.setStyleSheet(text_label.styleSheet() + " QLabel { color: #e6eef0; }")

        # Row layout to align left or right
        row = QtWidgets.QHBoxLayout()
        row.setContentsMargins(6, 6, 6, 6)
        if is_me:
            row.addStretch()
            row.addWidget(container, 0)
        else:
            row.addWidget(container, 0)
            row.addStretch()

        self.setLayout(row)


# --- Main Window ---
class ChatWindow(QtWidgets.QMainWindow):
    # signal emitted from receiver thread with (kind, payload) where kind in {"keys_update", "message", "system"}
    network_signal = Signal(str, dict)

    def __init__(self):
        super().__init__()
        self.setWindowTitle("Secure WhatsApp Pro (PySide6)")
        self.resize(900, 700)
        self.setStyleSheet("QMainWindow { background: #0f1720; }")

        # central layout
        central = QtWidgets.QWidget()
        self.setCentralWidget(central)
        main_layout = QtWidgets.QHBoxLayout(central)
        main_layout.setContentsMargins(12, 12, 12, 12)
        main_layout.setSpacing(12)

        # ---- Sidebar (contacts / clients) ----
        sidebar = QtWidgets.QFrame()
        sidebar.setFixedWidth(240)
        sidebar.setStyleSheet("QFrame { background: #111827; border-radius:8px; }")
        sb_layout = QtWidgets.QVBoxLayout(sidebar)
        sb_layout.setContentsMargins(10, 10, 10, 10)
        sb_layout.setSpacing(8)

        header_label = QtWidgets.QLabel("Contacts")
        header_label.setStyleSheet("QLabel { color: #e6eef0; font-weight:700; font-size:16px; }")
        sb_layout.addWidget(header_label)

        self.contacts_list = QtWidgets.QListWidget()
        self.contacts_list.setStyleSheet(
            "QListWidget { background: transparent; color: #cfe8df; border: none; font-size:13px; }"
            "QListWidget::item:selected { background: #0b5542; }"
        )
        sb_layout.addWidget(self.contacts_list, 1)

        refresh_btn = QtWidgets.QPushButton("Refresh keys")
        refresh_btn.setCursor(QtGui.QCursor(QtCore.Qt.PointingHandCursor))
        refresh_btn.setStyleSheet("QPushButton { background: #0b5542; color: white; padding:8px; border-radius:6px; }")
        refresh_btn.clicked.connect(self.request_keys_update)
        sb_layout.addWidget(refresh_btn)

        main_layout.addWidget(sidebar)

        # ---- Chat area ----
        right_frame = QtWidgets.QFrame()
        right_frame.setStyleSheet("QFrame { background: transparent; }")
        right_layout = QtWidgets.QVBoxLayout(right_frame)
        right_layout.setContentsMargins(0, 0, 0, 0)
        right_layout.setSpacing(8)

        # top header bar
        top_bar = QtWidgets.QFrame()
        top_bar.setFixedHeight(64)
        top_bar.setStyleSheet("QFrame { background: #075E54; border-radius:6px; }")
        top_layout = QtWidgets.QHBoxLayout(top_bar)
        top_layout.setContentsMargins(12, 8, 12, 8)

        title = QtWidgets.QLabel("Secure WhatsApp Pro")
        title.setStyleSheet("QLabel { color: white; font-weight:700; font-size:18px; }")
        top_layout.addWidget(title)
        top_layout.addStretch()
        self.status_label = QtWidgets.QLabel("Connected")
        self.status_label.setStyleSheet("QLabel { color: #d1e7df; }")
        top_layout.addWidget(self.status_label)

        right_layout.addWidget(top_bar)

        # scroll area for messages
        self.scroll_area = QtWidgets.QScrollArea()
        self.scroll_area.setWidgetResizable(True)
        self.scroll_area.setStyleSheet("QScrollArea { border: none; }")
        self.msg_container = QtWidgets.QWidget()
        self.msg_layout = QtWidgets.QVBoxLayout(self.msg_container)
        self.msg_layout.setContentsMargins(8, 8, 8, 8)
        self.msg_layout.setSpacing(4)
        self.msg_layout.addStretch()  # push messages up
        self.scroll_area.setWidget(self.msg_container)
        right_layout.addWidget(self.scroll_area, 1)

        # input row
        input_row = QtWidgets.QFrame()
        input_row.setFixedHeight(84)
        input_row.setStyleSheet("QFrame { background: #07121a; border-radius:8px; }")
        input_layout = QtWidgets.QHBoxLayout(input_row)
        input_layout.setContentsMargins(12, 12, 12, 12)
        input_layout.setSpacing(8)

        self.input_field = QtWidgets.QLineEdit()
        self.input_field.setPlaceholderText("Type a message...")
        self.input_field.returnPressed.connect(self.on_send_clicked)
        self.input_field.setStyleSheet(
            "QLineEdit { background: #071b1a; color: #e8f7f2; padding:10px; border-radius:14px; border: 1px solid #0b5542; }"
        )
        input_layout.addWidget(self.input_field, 1)

        self.send_btn = QtWidgets.QPushButton("Send")
        self.send_btn.setCursor(QtGui.QCursor(QtCore.Qt.PointingHandCursor))
        self.send_btn.clicked.connect(self.on_send_clicked)
        self.send_btn.setStyleSheet("QPushButton { background: #25D366; color: #01281a; padding:10px 18px; font-weight:700; border-radius:14px; }"
                                    "QPushButton:hover { background:#1DA851; }")
        input_layout.addWidget(self.send_btn)

        right_layout.addWidget(input_row)

        main_layout.addWidget(right_frame, 1)

        # networking state
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self.sock.connect((HOST, PORT))
            self.status_label.setText("Connected")
        except Exception as e:
            self.status_label.setText(f"Disconnected: {e}")

        # send our public key immediately
        try:
            serialized_pub = serialize_public_key(public_key)
            self.sock.send(serialized_pub.encode())
        except Exception:
            pass

        # data structures
        self.clients_public_keys = {}  # addr_str -> public_key_object
        self.client_names = {}         # addr_str -> "Client X"
        self.running = True

        # connect signal
        self.network_signal.connect(self.on_network_event)

        # start receiver thread
        threading.Thread(target=self.receiver_loop, daemon=True).start()

    # --- UI helpers ---
    def add_bubble(self, text: str, name: str = "", me: bool = False):
        bubble = MessageBubble(text, name, is_me=me)
        # insert before the stretch at the end
        self.msg_layout.insertWidget(self.msg_layout.count() - 1, bubble)
        QtCore.QTimer.singleShot(50, self.scroll_to_bottom)  # let layout update then scroll

    def scroll_to_bottom(self):
        self.scroll_area.verticalScrollBar().setValue(self.scroll_area.verticalScrollBar().maximum())

    # --- user actions ---
    @Slot()
    def on_send_clicked(self):
        text = self.input_field.text().strip()
        if not text:
            return
        # Sign message
        try:
            signature = sign_message(private_key, text)
        except Exception:
            signature = b""

        # For every known client pubkey, encrypt and send
        for addr, pub in self.clients_public_keys.items():
            try:
                encrypted = encrypt_message(pub, text)
                packet = {
                    "ciphertext": encrypted.hex(),
                    "signature": signature.hex(),
                    "sender_addr": str(self.sock.getsockname())
                }
                self.sock.send(json.dumps(packet).encode())
            except Exception as e:
                # show system message locally if send to that peer fails
                self.network_signal.emit("system", {"text": f"Send error to {addr}: {e}"})

        # show own message
        self.add_bubble(text, name="You", me=True)
        self.input_field.clear()
        self.play_send_sound()

    def request_keys_update(self):
        try:
            req = json.dumps({"request": "keys_update"})
            self.sock.send(req.encode())
        except Exception as e:
            self.network_signal.emit("system", {"text": f"Failed to request keys: {e}"})

    # --- network receiver (background thread) ---
    def receiver_loop(self):
        while self.running:
            try:
                raw = self.sock.recv(16384)
                if not raw:
                    break
                # Try parse JSON
                try:
                    obj = json.loads(raw.decode())
                except Exception:
                    continue

                # keys update broadcast
                if "keys_update" in obj:
                    self.network_signal.emit("keys_update", {"keys": obj["keys_update"]})
                    continue

                # ciphertext message
                if "ciphertext" in obj:
                    self.network_signal.emit("message", obj)
                    continue

            except Exception as e:
                self.network_signal.emit("system", {"text": f"Network error: {e}"})
                break

        self.network_signal.emit("system", {"text": "Disconnected from server."})

    # --- main UI handler for network events (runs in main thread) ---
    @Slot(str, dict)
    def on_network_event(self, kind: str, payload: dict):
        if kind == "system":
            text = payload.get("text", "")
            self.add_bubble(text, name="", me=False)
            return

        if kind == "keys_update":
            keys = payload.get("keys", {})
            # rebuild maps
            self.clients_public_keys.clear()
            self.client_names.clear()
            my_addr = str(self.sock.getsockname())
            counter = 1
            # populate list widget
            self.contacts_list.clear()
            for addr, pem in keys.items():
                if addr == my_addr:
                    continue
                try:
                    pub = serialization.load_pem_public_key(pem.encode())
                    self.clients_public_keys[addr] = pub
                    name = f"Client {counter + 1}"
                    self.client_names[addr] = name
                    self.contacts_list.addItem(f"{name} — {addr}")
                    counter += 1
                except Exception:
                    continue
            self.add_bubble("[Keys updated]", me=False)

            return

        if kind == "message":
            obj = payload
            try:
                ciphertext = bytes.fromhex(obj["ciphertext"])
                signature = bytes.fromhex(obj.get("signature", ""))
                sender_addr = obj.get("sender_addr", "Unknown")
                # decrypt locally
                try:
                    plaintext = decrypt_message(private_key, ciphertext)
                except Exception:
                    # cannot decrypt — not meant for us
                    return
                # get display name
                display_name = self.client_names.get(sender_addr, sender_addr)
                # verify signature if we know the sender public key
                sender_pub = self.clients_public_keys.get(sender_addr)
                if sender_pub:
                    try:
                        ok = verify_signature(sender_pub, plaintext, signature)
                    except Exception:
                        ok = False
                    if ok:
                        self.add_bubble(plaintext, name=display_name, me=False)
                    else:
                        self.add_bubble(f"{display_name}: {plaintext} (unverified)", name=display_name, me=False)
                else:
                    # unknown sender public key, still show plaintext
                    self.add_bubble(plaintext, name=display_name, me=False)
            except Exception as e:
                self.add_bubble(f"Malformed message: {e}", name="", me=False)

    def play_send_sound(self):
        try:
            pygame.mixer.init()
            if os.path.exists("send_sound.mp3"):
                pygame.mixer.music.load("send_sound.mp3")
                pygame.mixer.music.play()
        except Exception:
            pass

    def closeEvent(self, event: QtGui.QCloseEvent) -> None:
        # cleanup
        self.running = False
        try:
            self.sock.shutdown(socket.SHUT_RDWR)
        except Exception:
            pass
        try:
            self.sock.close()
        except Exception:
            pass
        event.accept()


# --- run app ---
if __name__ == "__main__":
    app = QtWidgets.QApplication(sys.argv)
    w = ChatWindow()
    w.show()
    sys.exit(app.exec())

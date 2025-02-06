import os
import fcntl
import struct
import subprocess
import socket
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa, padding as a_padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
import os
from cryptography.hazmat.primitives import padding as pad
import threading
import json


class TUN:
    TUNSETIFF = 0x400454ca
    IFF_TUN = 0x0001
    IFF_NO_PI = 0x1000

    def __init__(self, dev_name="tun1"):
        self.dev_name = dev_name
        self.tun_fd = self.create_tun()
        self.configure_tun()

    def create_tun(self):
        try:
            tun_fd = os.open("/dev/net/tun", os.O_RDWR)
            ifr = struct.pack("16sH", self.dev_name.encode(), self.IFF_TUN | self.IFF_NO_PI)
            fcntl.ioctl(tun_fd, self.TUNSETIFF, ifr)
            print(f"TUN-интерфейс {self.dev_name} создан")
            return tun_fd
        except Exception as e:
            print(f"Ошибка при создании интерфейса: {e}")
            raise

    def configure_tun(self, ip="10.0.0.2", netmask="255.255.255.0"):
        try:
            subprocess.run(["ip", "addr", "add", f"{ip}/24", "dev", self.dev_name], check=True)
            subprocess.run(["ip", "link", "set", "dev", self.dev_name, "up"], check=True)
            print(f"TUN-интерфейс {self.dev_name} настроен по {ip}")
        except subprocess.CalledProcessError as e:
            print(f"Ошибка настройки: {e}")
            raise

    def read(self, buffer_size=4096):
        print("read")
        k = os.read(self.tun_fd, buffer_size)
        print(k.decode("utf-8", errors="ignore"))
        return k

    def write(self, data):
        print("write")
        print(data.decode("utf-8", errors="ignore"))
        os.write(self.tun_fd, data)

    def close(self):
        try:
            os.close(self.tun_fd)
            print(f"TUN-интерфейс {self.dev_name} отключей")
        except Exception as e:
            print(f"Ошибка отключения интерфейса: {e}")


class Encryption():
    def __init__(self, aes_key):
        self.aes_key = aes_key
        self.backend = default_backend()

    def encrypt_aes(self, data):
        if not data:
            raise ValueError("Информации для шифрования отсутствует")
        try:
            iv = os.urandom(16)
            padder = pad.PKCS7(128).padder()
            padded_data = padder.update(data) + padder.finalize()
            cipher = Cipher(algorithms.AES(self.aes_key), modes.CBC(iv), backend=self.backend)
            encryptor = cipher.encryptor()
            encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
            return iv + encrypted_data
        except Exception as e:
            print(f"Ошибка шифрования aes: {e}")
            return None
    
    def decrypt_aes(self, encrypted_data):
        try:
            if len(encrypted_data) < 16:
                raise ValueError("Слишком мало информации")
            iv = encrypted_data[:16]
            encrypted_data = encrypted_data[16:]
            cipher = Cipher(algorithms.AES(self.aes_key), modes.CBC(iv), backend=self.backend)
            decryptor = cipher.decryptor()
            decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()
            unpadder = pad.PKCS7(128).unpadder()
            data = unpadder.update(decrypted_data) + unpadder.finalize()
            return data
        except ValueError as e:
            print(f"Ошибка, связанная с Padding: {e}")
            return None
        except Exception as e:
            print(f"Ошибка дешифрования: {e}")
            return None
    
    def encrypt_rsa(self, rsa, data):
        try:
            rsa = serialization.load_pem_public_key(
                rsa,
                backend=self.backend
            )
            encrypted_aes = rsa.encrypt(
                data,
                a_padding.OAEP(
                    mgf=a_padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )   
            )
            return encrypted_aes
        except Exception as e:
            print(f"Ошибка дешифрования рса: {e}")
            return None


class Client:
    def __init__(self, ip, port):
        self.addr = (ip, port)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.settimeout(100000)
        self.aes_key = os.urandom(32)
        self.enc = Encryption(self.aes_key)
        self.tun = TUN()
        self.cleaned_up = False
    
    def connect_to(self):
        try:
            self.sock.connect(self.addr)
            print(f"Подключено к серверу по адресу: {self.addr}")
            rsa_key = self.sock.recv(4096)
            encr_aes = self.enc.encrypt_rsa(rsa_key, self.aes_key)
            self.sock.sendall(encr_aes)
        except Exception as e:
            print(f"Ошибка подключения: {e}")
            self.cleanup()
            exit(1)
    
    def handle_server(self):
        try:
            while True:
                encrypted_data = self.sock.recv(4096)
                if not encrypted_data:
                    print("Отключено от сервера")
                    break
                decrypted_data = self.enc.decrypt_aes(encrypted_data)
                if decrypted_data:
                    self.tun.write(decrypted_data)
        except Exception as e:
            print(f"Ошибка получения данных: {e}")
        finally:
            self.cleanup()

    def handle_tun(self):
        try:
            while True:
                packet = self.tun.read()
                print("sent")
                print(packet.decode('utf-8', errors='ignore'))
                encrypted_packet = self.enc.encrypt_aes(packet)
                if encrypted_packet:
                    self.sock.send(encrypted_packet)
        except Exception as e:
            print(f"Ошибка отправки данных: {e}")
        finally:
            self.cleanup()
    
    def cleanup(self):
        if self.cleaned_up:
            return
        self.cleaned_up = True

        try:
            if self.tun:
                self.tun.close()
            if self.sock:
                self.sock.close()
        except Exception as e:
            print(f"Ошибка при отключении: {e}")
        print("Все лишние подключения отключены")
    
    def start(self):
        self.connect_to()
        server_thread = threading.Thread(target=self.handle_server, daemon=True)
        tun_thread = threading.Thread(target=self.handle_tun, daemon=True)
        server_thread.start()
        tun_thread.start()
        server_thread.join()
        tun_thread.join()


if __name__ == "__main__":
    with open("/home/root123123/Документы/client_new/client/client_config.json", "r") as config_file:
        config = json.load(config_file)
    ip = config["server_ip"]
    port = config["server_port"]
    client = Client(ip, port)
    client.start()

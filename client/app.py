import tkinter as tk
from tkinter import messagebox, simpledialog
import sys
import os
import base64

# Add parent directory to sys.path so we can import shared
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from network import NetworkClient
from shared.crypto import CryptoUtils

class SecureChatApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure Chat Application")
        self.root.geometry("400x500")

        self.network = NetworkClient()
        self.network.set_receive_callback(self.handle_server_message)
        
        # Crypto state
        self.private_key = None
        self.public_key = None
        self.aes_keys = {} # Mapping of target_username -> AES key
        
        self.username = None
        self.current_chat_user = None

        self.setup_login_ui()

    def handle_server_message(self, response):
        action = response.get('action')
        
        if action == 'RECEIVE_MSG':
            sender = response['from']
            encrypted_content_b64 = response['encrypted_content']
            encrypted_content = base64.b64decode(encrypted_content_b64)
            
            # Check if we have an AES key for this sender
            if sender not in self.aes_keys:
                # In a real app we'd request the key or wait. 
                # For simplicity, if we don't have it, we might not be able to decrypt.
                self.display_message(f"[{sender}]: <Encrypted Message - No Key>")
                return
            
            aes_key = self.aes_keys[sender]
            try:
                decrypted_bytes = CryptoUtils.decrypt_aes(aes_key, encrypted_content)
                decrypted_msg = decrypted_bytes.decode('utf-8')
                if self.current_chat_user == sender:
                    self.display_message(f"[{sender}]: {decrypted_msg}")
            except Exception as e:
                self.display_message(f"[{sender}]: <Decryption Failed>")

        elif response.get('status') == 'success' and 'public_key' in response:
            # We received a public key for a user we requested
            target_user = self.current_chat_user
            pub_key_pem = response['public_key'].encode('utf-8')
            target_pub_key = CryptoUtils.deserialize_public_key(pub_key_pem)
            
            # Generate AES key for this chat
            aes_key = CryptoUtils.generate_aes_key()
            self.aes_keys[target_user] = aes_key
            
            # Display chat UI
            self.setup_chat_ui()
            self.display_message(f"--- Secure session established with {target_user} ---")

        elif response.get('status') == 'success':
            msg = response.get('message', '')
            if msg:
                messagebox.showinfo("Success", msg)

        elif response.get('status') == 'error':
            messagebox.showerror("Error", response.get('message', 'Unknown error'))

    def setup_login_ui(self):
        self.clear_window()
        
        tk.Label(self.root, text="Login / Register", font=("Helvetica", 16)).pack(pady=20)
        
        tk.Label(self.root, text="Username").pack()
        self.username_entry = tk.Entry(self.root)
        self.username_entry.pack(pady=5)
        
        tk.Label(self.root, text="Password").pack()
        self.password_entry = tk.Entry(self.root, show="*")
        self.password_entry.pack(pady=5)
        
        tk.Button(self.root, text="Login", command=self.login).pack(pady=5)
        tk.Button(self.root, text="Register", command=self.register).pack(pady=5)
        
        tk.Button(self.root, text="Connect", command=self.connect_to_server).pack(pady=20)
        self.conn_label = tk.Label(self.root, text="Not Connected", fg="red")
        self.conn_label.pack()

    def connect_to_server(self):
        self.conn_label.config(text="Searching for server on network...", fg="blue")
        self.root.update()
        
        if self.network.connect():
            self.conn_label.config(text=f"Connected to Server ({self.network.host})", fg="green")
        else:
            self.conn_label.config(text="Not Connected", fg="red")
            messagebox.showerror("Error", "Could not connect to server.")

    def generate_keys_if_needed(self):
        if not self.private_key:
            self.private_key, self.public_key = CryptoUtils.generate_rsa_key_pair()

    def register(self):
        if not self.network.connected:
            messagebox.showerror("Error", "Connect to server first!")
            return
            
        username = self.username_entry.get()
        password = self.password_entry.get()
        
        self.generate_keys_if_needed()
        pub_key_pem = CryptoUtils.serialize_public_key(self.public_key).decode('utf-8')
        
        self.network.send_request({
            'action': 'REGISTER',
            'username': username,
            'password': password,
            'public_key': pub_key_pem
        })
        messagebox.showinfo("Info", "Registration request sent. Check server logs if unsure. You can try logging in now.")

    def login(self):
        if not self.network.connected:
            messagebox.showerror("Error", "Connect to server first!")
            return
            
        self.username = self.username_entry.get()
        password = self.password_entry.get()
        
        totp_token = simpledialog.askstring("2FA", "Enter your 6-digit Authenticator code:")
        if not totp_token:
            return
        
        self.network.send_request({
            'action': 'LOGIN',
            'username': self.username,
            'password': password,
            'totp_token': totp_token
        })
        
        self.generate_keys_if_needed()
        self.setup_user_selection_ui()

    def setup_user_selection_ui(self):
        self.clear_window()
        tk.Label(self.root, text=f"Welcome {self.username}", font=("Helvetica", 16)).pack(pady=20)
        tk.Label(self.root, text="Enter username to chat with:").pack()
        
        self.target_entry = tk.Entry(self.root)
        self.target_entry.pack(pady=5)
        
        tk.Button(self.root, text="Start Chat", command=self.start_chat).pack(pady=10)

    def start_chat(self):
        target = self.target_entry.get()
        if not target:
            return
        
        self.current_chat_user = target
        
        # Request public key of target user
        self.network.send_request({
            'action': 'GET_KEY',
            'target_user': target
        })

    def setup_chat_ui(self):
        self.clear_window()
        
        tk.Label(self.root, text=f"Chat with {self.current_chat_user}", font=("Helvetica", 14)).pack(pady=5)
        
        self.chat_area = tk.Text(self.root, state='disabled', width=45, height=20)
        self.chat_area.pack(pady=5, padx=5)
        
        # Data Loss Prevention (DLP): Disable Copying
        self.chat_area.bind("<Control-c>", lambda e: "break")
        self.chat_area.bind("<Command-c>", lambda e: "break")
        self.chat_area.bind("<Button-3>", lambda e: "break") # Disable right click
        
        self.msg_entry = tk.Entry(self.root, width=35)
        self.msg_entry.pack(side=tk.LEFT, padx=5, pady=5)
        
        tk.Button(self.root, text="Send", command=self.send_message).pack(side=tk.RIGHT, padx=5, pady=5)

    def display_message(self, text):
        if hasattr(self, 'chat_area'):
            self.chat_area.config(state='normal')
            self.chat_area.insert(tk.END, text + "\n")
            self.chat_area.see(tk.END)
            self.chat_area.config(state='disabled')

    def send_message(self):
        msg = self.msg_entry.get()
        if not msg:
            return
            
        aes_key = self.aes_keys.get(self.current_chat_user)
        if not aes_key:
            messagebox.showerror("Error", "No AES key established for this user.")
            return
            
        encrypted_bytes = CryptoUtils.encrypt_aes(aes_key, msg.encode('utf-8'))
        encrypted_b64 = base64.b64encode(encrypted_bytes).decode('utf-8')
        
        self.network.send_request({
            'action': 'SEND_MSG',
            'target_user': self.current_chat_user,
            'encrypted_content': encrypted_b64
        })
        
        self.display_message(f"[You]: {msg}")
        self.msg_entry.delete(0, tk.END)

    def clear_window(self):
        for widget in self.root.winfo_children():
            widget.destroy()

if __name__ == "__main__":
    root = tk.Tk()
    app = SecureChatApp(root)
    root.mainloop()

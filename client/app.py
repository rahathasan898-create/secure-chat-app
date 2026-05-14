import tkinter as tk
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
        self.root.geometry("450x600")
        
        # Custom Dark Theme Colors
        self.bg_color = "#2E3440"
        self.fg_color = "#D8DEE9"
        self.entry_bg = "#4C566A"
        self.accent_color = "#88C0D0"
        
        self.root.configure(bg=self.bg_color)
        self.main_frame = None

        self.network = NetworkClient()
        self.network.set_receive_callback(lambda res: self.root.after(0, self.handle_server_message, res))
        
        # Crypto state
        self.private_key = None
        self.public_key = None
        self.aes_keys = {} # Mapping of target_username -> AES key
        
        self.username = None
        self.current_chat_user = None

        self.setup_login_ui()
        
        # Start auto-connection in background
        import threading
        threading.Thread(target=self.auto_connect, daemon=True).start()

    def create_label(self, parent, text, **kwargs):
        font = kwargs.pop('font', ("Helvetica", 14))
        fg = kwargs.pop('fg', self.fg_color)
        return tk.Label(parent, text=text, bg=self.bg_color, fg=fg, font=font, **kwargs)

    def create_entry(self, parent, **kwargs):
        return tk.Entry(parent, bg=self.entry_bg, fg=self.fg_color, insertbackground=self.fg_color, highlightbackground=self.bg_color, highlightthickness=1, font=("Helvetica", 14), **kwargs)

    def create_button(self, parent, text, command, **kwargs):
        return tk.Button(parent, text=text, command=command, highlightbackground=self.bg_color, font=("Helvetica", 14), **kwargs)

    def show_message(self, title, msg, is_error=False):
        print(f"SHOW_MESSAGE -> Title: {title} | Msg: {msg}")
        top = tk.Toplevel(self.root)
        top.title(title)
        top.geometry("350x200")
        top.configure(bg=self.bg_color)
        
        color = "#BF616A" if is_error else "#A3BE8C"
        tk.Label(top, text=msg, bg=self.bg_color, fg=color, font=("Helvetica", 14), wraplength=300, justify=tk.CENTER).pack(pady=(30, 20), expand=True)
        self.create_button(top, "OK", command=top.destroy).pack(pady=(0, 20))

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
                self.show_message("Success", msg)

        elif response.get('status') == 'error':
            self.show_message("Error", response.get('message', 'Unknown error'), is_error=True)

    def setup_login_ui(self):
        self.clear_window()
        
        self.create_label(self.main_frame, "Secure Chat", font=("Helvetica", 24, "bold"), fg=self.accent_color).pack(pady=(20, 30))
        
        self.create_label(self.main_frame, "Username").pack(anchor=tk.W, padx=20)
        self.username_entry = self.create_entry(self.main_frame)
        self.username_entry.pack(pady=(0, 15), padx=20, fill=tk.X)
        
        self.create_label(self.main_frame, "Password").pack(anchor=tk.W, padx=20)
        self.password_entry = self.create_entry(self.main_frame, show="*")
        self.password_entry.pack(pady=(0, 15), padx=20, fill=tk.X)
        
        self.create_label(self.main_frame, "2FA Token (Leave blank if registering)").pack(anchor=tk.W, padx=20)
        self.totp_entry = self.create_entry(self.main_frame)
        self.totp_entry.pack(pady=(0, 25), padx=20, fill=tk.X)
        
        btn_frame = tk.Frame(self.main_frame, bg=self.bg_color)
        btn_frame.pack(fill=tk.X, padx=20)
        
        self.create_button(btn_frame, "Login", command=self.login).pack(side=tk.LEFT, expand=True, fill=tk.X, padx=(0, 5))
        self.create_button(btn_frame, "Register", command=self.register).pack(side=tk.RIGHT, expand=True, fill=tk.X, padx=(5, 0))
        
        self.conn_label = self.create_label(self.main_frame, "Not Connected", fg="#BF616A")
        self.conn_label.pack(pady=(30, 5))
        
        self.retry_btn = self.create_button(self.main_frame, "Retry Connection", command=lambda: __import__('threading').Thread(target=self.auto_connect, daemon=True).start())
        # We don't pack retry_btn yet; only if it fails to connect

    def auto_connect(self):
        def start_search():
            try:
                self.conn_label.config(text="Searching for server on network...", fg="#81A1C1")
                self.retry_btn.pack_forget()
            except tk.TclError:
                pass
                
        def on_result(success):
            try:
                if success:
                    self.conn_label.config(text=f"Connected to Server ({self.network.host})", fg="#A3BE8C")
                else:
                    self.conn_label.config(text="Not Connected", fg="#BF616A")
                    self.retry_btn.pack(pady=5)
            except tk.TclError:
                pass
                
        self.root.after(0, start_search)
        success = self.network.connect()
        self.root.after(0, on_result, success)

    def generate_keys_if_needed(self):
        if not self.private_key:
            self.private_key, self.public_key = CryptoUtils.generate_rsa_key_pair()

    def register(self):
        if not self.network.connected:
            self.show_message("Error", "Connect to server first!", is_error=True)
            return
            
        username = self.username_entry.get().strip()
        password = self.password_entry.get()
        
        if not username or not password:
            self.show_message("Missing Info", "Please enter both a username and a password to register.", is_error=True)
            return
        
        self.generate_keys_if_needed()
        pub_key_pem = CryptoUtils.serialize_public_key(self.public_key).decode('utf-8')
        
        self.network.send_request({
            'action': 'REGISTER',
            'username': username,
            'password': password,
            'public_key': pub_key_pem
        })
        self.show_message("Info", "Registration request sent. Check server logs if unsure. You can try logging in now.")

    def login(self):
        if not self.network.connected:
            self.show_message("Error", "Connect to server first!", is_error=True)
            return
            
        self.username = self.username_entry.get().strip()
        password = self.password_entry.get()
        totp_token = self.totp_entry.get().strip()
        
        if not self.username or not password:
            self.show_message("Missing Info", "Please enter both your username and password to login.", is_error=True)
            return
            
        if not totp_token:
            self.show_message("Missing 2FA", "Please enter your 6-digit Authenticator code. If you haven't registered yet, click Register instead!", is_error=True)
            return
        
        self.network.send_request({
            'action': 'LOGIN',
            'username': self.username,
            'password': password,
            'totp_token': totp_token
        })

    def setup_user_selection_ui(self):
        self.clear_window()
        self.create_label(self.main_frame, f"Welcome {self.username}", font=("Helvetica", 20, "bold"), fg=self.accent_color).pack(pady=(20, 30))
        self.create_label(self.main_frame, "Enter username to chat with:").pack(anchor=tk.W, padx=20)
        
        self.target_entry = self.create_entry(self.main_frame)
        self.target_entry.pack(pady=(0, 20), padx=20, fill=tk.X)
        
        self.create_button(self.main_frame, "Start Chat", command=self.start_chat).pack(fill=tk.X, padx=20)

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
        
        self.create_label(self.main_frame, f"Chatting with {self.current_chat_user}", font=("Helvetica", 16, "bold"), fg=self.accent_color).pack(pady=(0, 10))
        
        self.chat_area = tk.Text(self.main_frame, state='disabled', width=45, height=20, font=("Helvetica", 13), bg=self.entry_bg, fg=self.fg_color, insertbackground=self.fg_color, highlightbackground=self.bg_color)
        self.chat_area.pack(pady=5, padx=10, fill=tk.BOTH, expand=True)
        
        # Data Loss Prevention (DLP): Disable Copying
        self.chat_area.bind("<Control-c>", lambda e: "break")
        self.chat_area.bind("<Command-c>", lambda e: "break")
        self.chat_area.bind("<Button-3>", lambda e: "break") # Disable right click
        
        bottom_frame = tk.Frame(self.main_frame, bg=self.bg_color)
        bottom_frame.pack(fill=tk.X, padx=10, pady=(10, 10))
        
        self.msg_entry = self.create_entry(bottom_frame)
        self.msg_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 10))
        
        self.create_button(bottom_frame, "Send", command=self.send_message).pack(side=tk.RIGHT)

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
            self.show_message("Error", "No AES key established for this user.", is_error=True)
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
        self.main_frame = tk.Frame(self.root, bg=self.bg_color)
        self.main_frame.pack(fill=tk.BOTH, expand=True)

if __name__ == "__main__":
    root = tk.Tk()
    app = SecureChatApp(root)
    root.mainloop()

import sqlite3
import bcrypt
import pyotp

class Database:
    def __init__(self, db_path="server_database.db"):
        self.db_path = db_path
        self._initialize_db()

    def _initialize_db(self):
        """Creates tables if they do not exist."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            # Users table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    public_key_pem TEXT,
                    role TEXT DEFAULT 'user',
                    totp_secret TEXT
                )
            ''')
            
            # Messages table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS messages (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    sender_id INTEGER NOT NULL,
                    receiver_id INTEGER NOT NULL,
                    encrypted_content BLOB NOT NULL,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (sender_id) REFERENCES users (id),
                    FOREIGN KEY (receiver_id) REFERENCES users (id)
                )
            ''')
            conn.commit()

    def register_user(self, username, password, public_key_pem, role='user'):
        """Registers a new user. Returns (True, totp_secret) on success, (False, None) if user exists."""
        password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        totp_secret = pyotp.random_base32()
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('INSERT INTO users (username, password_hash, public_key_pem, role, totp_secret) VALUES (?, ?, ?, ?, ?)',
                               (username, password_hash, public_key_pem, role, totp_secret))
                conn.commit()
                return True, totp_secret
        except sqlite3.IntegrityError:
            # Username already exists
            return False, None

    def authenticate_user(self, username, password):
        """Authenticates a user based on password. Returns (user_id, totp_secret, role) if successful, None otherwise."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT id, password_hash, totp_secret, role FROM users WHERE username = ?', (username,))
            result = cursor.fetchone()
            if result:
                user_id, password_hash, totp_secret, role = result
                if bcrypt.checkpw(password.encode('utf-8'), password_hash.encode('utf-8')):
                    return user_id, totp_secret, role
            return None

    def get_user_public_key(self, username):
        """Gets the public key of a given user."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT public_key_pem FROM users WHERE username = ?', (username,))
            result = cursor.fetchone()
            if result:
                return result[0]
            return None

    def store_message(self, sender_id, receiver_username, encrypted_content):
        """Stores an encrypted message."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            # Find receiver_id
            cursor.execute('SELECT id FROM users WHERE username = ?', (receiver_username,))
            result = cursor.fetchone()
            if not result:
                return False # Receiver not found
            receiver_id = result[0]
            
            cursor.execute('''
                INSERT INTO messages (sender_id, receiver_id, encrypted_content) 
                VALUES (?, ?, ?)
            ''', (sender_id, receiver_id, encrypted_content))
            conn.commit()
            return True

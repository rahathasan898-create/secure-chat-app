import sqlite3
import bcrypt
import pyotp
import os

from rbac import (
    MASTER_ADMIN_USERNAME,
    ROLE_MASTER_ADMIN,
    ROLE_USER,
    ASSIGNABLE_ROLES,
    normalize_role,
)

# Always use the same file next to this module (avoids a second empty DB when cwd differs).
_SERVER_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_DB_PATH = os.path.join(_SERVER_DIR, "server_database.db")


class Database:
    def __init__(self, db_path=None):
        self.db_path = db_path or DEFAULT_DB_PATH
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
            self._migrate_messages_columns()
            self._migrate_group_tables()
            self._migrate_display_name_column()
            self._migrate_totp_enrolled_column()

    def master_admin_exists(self):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                'SELECT 1 FROM users WHERE role = ? LIMIT 1',
                (ROLE_MASTER_ADMIN,),
            )
            return cursor.fetchone() is not None

    def _migrate_group_tables(self):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                '''
                CREATE TABLE IF NOT EXISTS groups (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    created_by_user_id INTEGER NOT NULL,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (created_by_user_id) REFERENCES users (id)
                )
                '''
            )
            cursor.execute(
                '''
                CREATE TABLE IF NOT EXISTS group_members (
                    group_id INTEGER NOT NULL,
                    user_id INTEGER NOT NULL,
                    PRIMARY KEY (group_id, user_id),
                    FOREIGN KEY (group_id) REFERENCES groups (id),
                    FOREIGN KEY (user_id) REFERENCES users (id)
                )
                '''
            )
            cursor.execute(
                '''
                CREATE TABLE IF NOT EXISTS group_key_wraps (
                    group_id INTEGER NOT NULL,
                    user_id INTEGER NOT NULL,
                    wrapped_key BLOB NOT NULL,
                    PRIMARY KEY (group_id, user_id),
                    FOREIGN KEY (group_id) REFERENCES groups (id),
                    FOREIGN KEY (user_id) REFERENCES users (id)
                )
                '''
            )
            cursor.execute(
                '''
                CREATE TABLE IF NOT EXISTS group_messages (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    group_id INTEGER NOT NULL,
                    sender_id INTEGER NOT NULL,
                    encrypted_content BLOB NOT NULL,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (group_id) REFERENCES groups (id),
                    FOREIGN KEY (sender_id) REFERENCES users (id)
                )
                '''
            )
            conn.commit()

    def _migrate_display_name_column(self):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('PRAGMA table_info(users)')
            cols = {row[1] for row in cursor.fetchall()}
            if 'display_name' not in cols:
                cursor.execute(
                    'ALTER TABLE users ADD COLUMN display_name TEXT'
                )
                cursor.execute(
                    'UPDATE users SET display_name = username WHERE display_name IS NULL'
                )
                conn.commit()

    def _migrate_totp_enrolled_column(self):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('PRAGMA table_info(users)')
            cols = {row[1] for row in cursor.fetchall()}
            if 'totp_enrolled' not in cols:
                cursor.execute(
                    'ALTER TABLE users ADD COLUMN totp_enrolled INTEGER NOT NULL DEFAULT 0'
                )
            cursor.execute(
                '''
                UPDATE users
                SET totp_enrolled = 1
                WHERE totp_secret IS NOT NULL AND totp_secret != ''
                  AND LOWER(username) != ?
                ''',
                (MASTER_ADMIN_USERNAME,),
            )
            cursor.execute(
                '''
                UPDATE users
                SET totp_secret = NULL, totp_enrolled = 0
                WHERE LOWER(username) = ?
                ''',
                (MASTER_ADMIN_USERNAME,),
            )
            conn.commit()

    def _migrate_messages_columns(self):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('PRAGMA table_info(messages)')
            cols = {row[1] for row in cursor.fetchall()}
            if 'encrypted_aes_key_receiver' not in cols:
                cursor.execute(
                    'ALTER TABLE messages ADD COLUMN encrypted_aes_key_receiver BLOB'
                )
                conn.commit()

    def _get_user_auth_row(self, username):
        uname = (username or '').strip()
        if not uname:
            return None
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute(
                '''
                SELECT id, username, password_hash, totp_secret, role, totp_enrolled
                FROM users WHERE username = ? COLLATE NOCASE
                ''',
                (uname,),
            )
            return cursor.fetchone()

    def verify_totp_for_username(self, username, totp_token):
        """Returns True if username exists and TOTP token is valid; marks enrolled on success."""
        row = self._get_user_auth_row(username)
        if not row or not row['totp_secret']:
            return False
        totp = pyotp.TOTP(row['totp_secret'])
        if not totp.verify(totp_token):
            return False
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                'UPDATE users SET totp_enrolled = 1 WHERE id = ?', (row['id'],)
            )
            conn.commit()
            return True

    def user_exists(self, username):
        if not (username or '').strip():
            return False
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                'SELECT 1 FROM users WHERE username = ? COLLATE NOCASE',
                (username.strip(),),
            )
            return cursor.fetchone() is not None

    def is_totp_enrolled(self, username):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                'SELECT totp_enrolled FROM users WHERE username = ?', (username,)
            )
            row = cursor.fetchone()
            return bool(row and row[0])

    def register_user(self, username, password, public_key_pem):
        """
        Register a new user. Returns (True, totp_secret) on success.
        Returns (False, None) if username taken or master admin slot is already filled.
        """
        uname = (username or '').strip()
        if not uname:
            return False, None
        role = ROLE_USER
        display_name = uname
        if uname.lower() == MASTER_ADMIN_USERNAME:
            if self.master_admin_exists():
                return False, None
            role = ROLE_MASTER_ADMIN
            display_name = 'Master Admin'
        password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        totp_secret = pyotp.random_base32()
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    '''
                    INSERT INTO users (
                        username, password_hash, public_key_pem, role,
                        totp_secret, display_name, totp_enrolled
                    ) VALUES (?, ?, ?, ?, ?, ?, 0)
                    ''',
                    (uname, password_hash, public_key_pem, role, totp_secret, display_name),
                )
                conn.commit()
                return True, totp_secret
        except sqlite3.IntegrityError:
            return self.resume_registration_totp(username, password, public_key_pem)

    def resume_registration_totp(self, username, password, public_key_pem=None):
        """
        User exists but has not finished 2FA setup (totp_enrolled=0).
        Return the existing TOTP secret when the password matches.
        """
        row = self._get_user_auth_row(username)
        if not row:
            return False, None
        if row['totp_enrolled']:
            return False, None
        if not bcrypt.checkpw(
            password.encode('utf-8'), row['password_hash'].encode('utf-8')
        ):
            return False, None
        totp_secret = row['totp_secret']
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            if not totp_secret:
                totp_secret = pyotp.random_base32()
                cursor.execute(
                    'UPDATE users SET totp_secret = ? WHERE id = ?',
                    (totp_secret, row['id']),
                )
            if public_key_pem:
                cursor.execute(
                    'UPDATE users SET public_key_pem = ? WHERE id = ?',
                    (public_key_pem, row['id']),
                )
            conn.commit()
        return True, totp_secret

    def authenticate_user(self, username, password):
        """Returns (user_id, totp_secret, role) if password matches, else None."""
        row = self._get_user_auth_row(username)
        if not row:
            return None
        if bcrypt.checkpw(password.encode('utf-8'), row['password_hash'].encode('utf-8')):
            return row['id'], row['totp_secret'], normalize_role(row['role'])
        return None

    def list_users_admin(self):
        """All users for admin/moderator dashboards."""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute(
                '''
                SELECT id, username, display_name, role,
                       CASE WHEN public_key_pem IS NOT NULL AND public_key_pem != ''
                            THEN 1 ELSE 0 END AS has_public_key
                FROM users
                ORDER BY username COLLATE NOCASE ASC
                '''
            )
            rows = cursor.fetchall()
            out = []
            for r in rows:
                out.append(
                    {
                        'user_id': r['id'],
                        'username': r['username'],
                        'display_name': r['display_name'] or r['username'],
                        'role': normalize_role(r['role']),
                        'has_public_key': bool(r['has_public_key']),
                    }
                )
            return out

    def set_user_role(self, actor_user_id, target_username, new_role):
        new_role = normalize_role(new_role)
        if new_role not in ASSIGNABLE_ROLES:
            return False, 'Invalid role'
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                'SELECT id, role FROM users WHERE username = ?', (target_username,)
            )
            row = cursor.fetchone()
            if not row:
                return False, 'User not found'
            target_id, current_role = row
            current_role = normalize_role(current_role)
            if current_role == ROLE_MASTER_ADMIN:
                return False, 'Cannot change master admin role'
            if target_id == actor_user_id:
                return False, 'Cannot change your own role'
            cursor.execute(
                'UPDATE users SET role = ? WHERE id = ?', (new_role, target_id)
            )
            conn.commit()
            return True, None

    def delete_user_admin(self, actor_user_id, target_username):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                'SELECT id, role FROM users WHERE username = ?', (target_username,)
            )
            row = cursor.fetchone()
            if not row:
                return False, 'User not found'
            target_id, role = row
            if normalize_role(role) == ROLE_MASTER_ADMIN:
                return False, 'Cannot delete master admin'
            if target_id == actor_user_id:
                return False, 'Cannot delete yourself'
            cursor.execute('DELETE FROM messages WHERE sender_id = ? OR receiver_id = ?',
                           (target_id, target_id))
            cursor.execute(
                'DELETE FROM group_messages WHERE sender_id = ?', (target_id,)
            )
            cursor.execute(
                'DELETE FROM group_members WHERE user_id = ?', (target_id,)
            )
            cursor.execute(
                'DELETE FROM group_key_wraps WHERE user_id = ?', (target_id,)
            )
            cursor.execute('DELETE FROM users WHERE id = ?', (target_id,))
            conn.commit()
            return True, None

    def delete_message_by_id(self, message_id):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('DELETE FROM messages WHERE id = ?', (message_id,))
            conn.commit()
            return cursor.rowcount > 0

    def delete_group_message_by_id(self, message_id):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('DELETE FROM group_messages WHERE id = ?', (message_id,))
            conn.commit()
            return cursor.rowcount > 0

    def get_user_public_key(self, username):
        """Gets the public key of a given user."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT public_key_pem FROM users WHERE username = ?', (username,))
            result = cursor.fetchone()
            if result:
                return result[0]
            return None

    def store_message(
        self,
        sender_id,
        receiver_username,
        encrypted_content,
        encrypted_aes_key_receiver=None,
    ):
        """Stores an encrypted message. encrypted_aes_key_receiver is RSA-wrapped AES key for the receiver (optional for legacy rows)."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            # Find receiver_id
            cursor.execute('SELECT id FROM users WHERE username = ?', (receiver_username,))
            result = cursor.fetchone()
            if not result:
                return None
            receiver_id = result[0]
            
            cursor.execute('''
                INSERT INTO messages (sender_id, receiver_id, encrypted_content, encrypted_aes_key_receiver) 
                VALUES (?, ?, ?, ?)
            ''', (sender_id, receiver_id, encrypted_content, encrypted_aes_key_receiver))
            conn.commit()
            return cursor.lastrowid

    def get_messages_for_thread(self, user_id, peer_username):
        """Returns message rows between user_id and peer (both directions), oldest first."""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute(
                '''
                SELECT m.id, m.timestamp, m.encrypted_content, m.encrypted_aes_key_receiver,
                       su.username AS sender_username, ru.username AS receiver_username
                FROM messages m
                JOIN users su ON m.sender_id = su.id
                JOIN users ru ON m.receiver_id = ru.id
                WHERE (m.sender_id = ? AND ru.username = ?)
                   OR (m.receiver_id = ? AND su.username = ?)
                ORDER BY m.id ASC
                ''',
                (user_id, peer_username, user_id, peer_username),
            )
            rows = cursor.fetchall()
            return [{k: r[k] for k in r.keys()} for r in rows]

    def get_all_users(self):
        """Returns a list of all registered usernames."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT username FROM users')
            results = cursor.fetchall()
            return [row[0] for row in results]

    def update_user_public_key(self, username, public_key_pem):
        """Updates the public key for an existing user."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('UPDATE users SET public_key_pem = ? WHERE username = ?', (public_key_pem, username))
            conn.commit()
            return True

    def get_user_profile(self, user_id):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                'SELECT username, display_name, role FROM users WHERE id = ?',
                (user_id,),
            )
            row = cursor.fetchone()
            if not row:
                return None
            username, display_name, role = row
            return {
                'username': username,
                'display_name': display_name or username,
                'role': role or 'user',
            }

    def update_display_name(self, user_id, display_name):
        name = (display_name or '').strip()[:80]
        if not name:
            return False
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                'UPDATE users SET display_name = ? WHERE id = ?',
                (name, user_id),
            )
            conn.commit()
            return cursor.rowcount > 0

    def get_message_participants(self, message_id):
        """Returns (sender_username, receiver_username) for a row, or None if missing."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                '''
                SELECT su.username, ru.username
                FROM messages m
                JOIN users su ON m.sender_id = su.id
                JOIN users ru ON m.receiver_id = ru.id
                WHERE m.id = ?
                ''',
                (message_id,),
            )
            row = cursor.fetchone()
            if not row:
                return None
            return row[0], row[1]

    def delete_message_if_participant(self, message_id, user_id):
        """Deletes a message row only if user_id is sender or receiver. Returns True if deleted."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                'SELECT sender_id, receiver_id FROM messages WHERE id = ?', (message_id,)
            )
            row = cursor.fetchone()
            if not row:
                return False
            sender_id, receiver_id = row
            if sender_id != user_id and receiver_id != user_id:
                return False
            cursor.execute('DELETE FROM messages WHERE id = ?', (message_id,))
            conn.commit()
            return True

    def resolve_usernames_to_ids(self, usernames):
        """Returns dict username -> user_id for existing users (subset of usernames)."""
        out = {}
        if not usernames:
            return out
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            for u in usernames:
                cursor.execute('SELECT id FROM users WHERE username = ?', (u,))
                row = cursor.fetchone()
                if row:
                    out[u] = row[0]
        return out

    def create_group(self, name, creator_id, member_id_to_wrap):
        """
        member_id_to_wrap: dict user_id -> wrapped_key bytes.
        Inserts group, members, and wraps in one transaction.
        Returns group_id or None on failure.
        """
        if not member_id_to_wrap:
            return None
        member_ids = set(member_id_to_wrap.keys())
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    'INSERT INTO groups (name, created_by_user_id) VALUES (?, ?)',
                    (name or 'Group', creator_id),
                )
                gid = cursor.lastrowid
                for uid in member_ids:
                    cursor.execute(
                        'INSERT INTO group_members (group_id, user_id) VALUES (?, ?)',
                        (gid, uid),
                    )
                for uid, blob in member_id_to_wrap.items():
                    cursor.execute(
                        '''
                        INSERT INTO group_key_wraps (group_id, user_id, wrapped_key)
                        VALUES (?, ?, ?)
                        ''',
                        (gid, uid, blob),
                    )
                conn.commit()
                return gid
        except sqlite3.IntegrityError:
            return None

    def list_groups_for_user(self, user_id):
        """Rows: group_id, name, wrapped_key (bytes), members (list of usernames)."""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute(
                '''
                SELECT g.id AS group_id, g.name, g.created_by_user_id, gkw.wrapped_key,
                       cu.username AS created_by_username
                FROM groups g
                JOIN group_members gm ON gm.group_id = g.id AND gm.user_id = ?
                JOIN group_key_wraps gkw ON gkw.group_id = g.id AND gkw.user_id = ?
                JOIN users cu ON cu.id = g.created_by_user_id
                ORDER BY g.id ASC
                ''',
                (user_id, user_id),
            )
            rows = cursor.fetchall()
            out = []
            for r in rows:
                gid = r['group_id']
                cursor.execute(
                    '''
                    SELECT u.username FROM group_members gm
                    JOIN users u ON u.id = gm.user_id
                    WHERE gm.group_id = ?
                    ORDER BY u.username
                    ''',
                    (gid,),
                )
                members = [row[0] for row in cursor.fetchall()]
                out.append(
                    {
                        'group_id': gid,
                        'name': r['name'],
                        'members': members,
                        'wrapped_key': r['wrapped_key'],
                        'created_by_user_id': r['created_by_user_id'],
                        'created_by_username': r['created_by_username'],
                    }
                )
            return out

    def rename_group(self, group_id, user_id, new_name):
        name = (new_name or '').strip()[:120]
        if not name:
            return False
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                'SELECT created_by_user_id FROM groups WHERE id = ?', (group_id,)
            )
            row = cursor.fetchone()
            if not row or row[0] != user_id:
                return False
            if not self.is_group_member(group_id, user_id):
                return False
            cursor.execute(
                'UPDATE groups SET name = ? WHERE id = ?', (name, group_id)
            )
            conn.commit()
            return cursor.rowcount > 0

    def delete_group(self, group_id, user_id):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                'SELECT created_by_user_id FROM groups WHERE id = ?', (group_id,)
            )
            row = cursor.fetchone()
            if not row or row[0] != user_id:
                return False
            cursor.execute('DELETE FROM group_messages WHERE group_id = ?', (group_id,))
            cursor.execute('DELETE FROM group_key_wraps WHERE group_id = ?', (group_id,))
            cursor.execute('DELETE FROM group_members WHERE group_id = ?', (group_id,))
            cursor.execute('DELETE FROM groups WHERE id = ?', (group_id,))
            conn.commit()
            return True

    def leave_group(self, group_id, user_id):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            if not self.is_group_member(group_id, user_id):
                return False
            cursor.execute(
                'SELECT COUNT(*) FROM group_members WHERE group_id = ?', (group_id,)
            )
            count = cursor.fetchone()[0]
            if count <= 1:
                return self.delete_group_as_last_member(group_id, user_id, cursor, conn)
            cursor.execute(
                'DELETE FROM group_key_wraps WHERE group_id = ? AND user_id = ?',
                (group_id, user_id),
            )
            cursor.execute(
                'DELETE FROM group_members WHERE group_id = ? AND user_id = ?',
                (group_id, user_id),
            )
            conn.commit()
            return True

    def delete_group_as_last_member(self, group_id, user_id, cursor=None, conn=None):
        own_conn = conn is None
        if own_conn:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
        cursor.execute(
            'SELECT created_by_user_id FROM groups WHERE id = ?', (group_id,)
        )
        row = cursor.fetchone()
        if not row:
            if own_conn:
                conn.close()
            return False
        cursor.execute('DELETE FROM group_messages WHERE group_id = ?', (group_id,))
        cursor.execute('DELETE FROM group_key_wraps WHERE group_id = ?', (group_id,))
        cursor.execute('DELETE FROM group_members WHERE group_id = ?', (group_id,))
        cursor.execute('DELETE FROM groups WHERE id = ?', (group_id,))
        conn.commit()
        if own_conn:
            conn.close()
        return True

    def is_group_member(self, group_id, user_id):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                'SELECT 1 FROM group_members WHERE group_id = ? AND user_id = ?',
                (group_id, user_id),
            )
            return cursor.fetchone() is not None

    def get_group_member_usernames(self, group_id):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                '''
                SELECT u.username FROM group_members gm
                JOIN users u ON u.id = gm.user_id
                WHERE gm.group_id = ?
                ''',
                (group_id,),
            )
            return [row[0] for row in cursor.fetchall()]

    def get_group_messages(self, group_id):
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute(
                '''
                SELECT gm.id, gm.timestamp, gm.encrypted_content, u.username AS sender_username
                FROM group_messages gm
                JOIN users u ON u.id = gm.sender_id
                WHERE gm.group_id = ?
                ORDER BY gm.id ASC
                ''',
                (group_id,),
            )
            rows = cursor.fetchall()
            return [{k: r[k] for k in r.keys()} for r in rows]

    def insert_group_message(self, group_id, sender_id, encrypted_content):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                '''
                INSERT INTO group_messages (group_id, sender_id, encrypted_content)
                VALUES (?, ?, ?)
                ''',
                (group_id, sender_id, encrypted_content),
            )
            conn.commit()
            return cursor.lastrowid

    def get_group_message_row(self, message_id):
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute(
                '''
                SELECT gm.id, gm.group_id, gm.sender_id, u.username AS sender_username
                FROM group_messages gm
                JOIN users u ON u.id = gm.sender_id
                WHERE gm.id = ?
                ''',
                (message_id,),
            )
            r = cursor.fetchone()
            if not r:
                return None
            return {k: r[k] for k in r.keys()}

    def delete_group_message_if_sender(self, message_id, user_id):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                'SELECT sender_id FROM group_messages WHERE id = ?', (message_id,)
            )
            row = cursor.fetchone()
            if not row or row[0] != user_id:
                return False
            cursor.execute('DELETE FROM group_messages WHERE id = ?', (message_id,))
            conn.commit()
            return True

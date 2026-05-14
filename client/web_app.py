import sys
import os
import base64
import threading
from flask import Flask, request, jsonify, render_template

# Add parent directory to sys.path so we can import shared and client modules
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from client.network import NetworkClient
from shared.crypto import CryptoUtils

app = Flask(__name__)

# Global state for the single local client
state = {
    'network': NetworkClient(),
    'private_key': None,
    'public_key': None,
    'aes_keys': {},
    'username': None,
    'messages': [],
    'connected': False,
    'last_error': None,
    'last_success': None,
    'last_totp': None,
    'target_user': None,
    'chat_active': False,
    'contacts': set()
}

def handle_server_message(response):
    action = response.get('action')
    
    if action == 'RECEIVE_MSG':
        sender = response['from']
        encrypted_content_b64 = response['encrypted_content']
        encrypted_content = base64.b64decode(encrypted_content_b64)
        
        if sender in state['aes_keys']:
            aes_key = state['aes_keys'][sender]
            try:
                decrypted_bytes = CryptoUtils.decrypt_aes(aes_key, encrypted_content)
                msg = decrypted_bytes.decode('utf-8')
                state['messages'].append({'sender': sender, 'text': msg})
            except:
                state['messages'].append({'sender': sender, 'text': '<Decryption Failed>'})
        else:
            state['messages'].append({'sender': sender, 'text': '<Encrypted Message - No Key>'})
            
    elif response.get('status') == 'success' and 'public_key' in response:
        target_user = state['target_user']
        pub_key_pem = response['public_key'].encode('utf-8')
        target_pub_key = CryptoUtils.deserialize_public_key(pub_key_pem)
        
        aes_key = CryptoUtils.generate_aes_key()
        state['aes_keys'][target_user] = aes_key
        state['chat_active'] = True
        state['contacts'].add(target_user)
        state['messages'].append({'sender': 'SYSTEM', 'text': f'Secure session established with {target_user}'})
        
    elif response.get('status') == 'success':
        msg = response.get('message', '')
        if 'totp_secret' in response:
            state['last_totp'] = response['totp_secret']
        if msg:
            # Check if this is a login success to transition state
            if "Login successful" in msg:
                state['username'] = state.get('_temp_username')
            state['last_success'] = msg
            
    elif response.get('status') == 'error':
        state['last_error'] = response.get('message', 'Unknown error')

state['network'].set_receive_callback(handle_server_message)

def generate_keys_if_needed():
    if not state['private_key']:
        state['private_key'], state['public_key'] = CryptoUtils.generate_rsa_key_pair()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/status', methods=['GET'])
def get_status():
    return jsonify({
        'connected': state['network'].connected,
        'username': state['username'],
        'target_user': state['target_user'],
        'chat_active': state['chat_active'],
        'messages': state['messages'],
        'error': state['last_error'],
        'success': state['last_success'],
        'totp': state['last_totp'],
        'contacts': list(state['contacts'])
    })

@app.route('/api/clear_messages', methods=['POST'])
def clear_msgs():
    state['last_error'] = None
    state['last_success'] = None
    state['last_totp'] = None
    return jsonify({'status': 'ok'})

@app.route('/api/connect', methods=['POST'])
def connect():
    if not state['network'].connected:
        threading.Thread(target=state['network'].connect, daemon=True).start()
    return jsonify({'status': 'connecting'})

@app.route('/api/register', methods=['POST'])
def register():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    
    if not state['network'].connected:
        return jsonify({'error': 'Not connected to server'})
        
    generate_keys_if_needed()
    pub_key_pem = CryptoUtils.serialize_public_key(state['public_key']).decode('utf-8')
    
    state['network'].send_request({
        'action': 'REGISTER',
        'username': username,
        'password': password,
        'public_key': pub_key_pem
    })
    return jsonify({'status': 'ok'})

@app.route('/api/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    totp_token = data.get('totp_token')
    
    if not state['network'].connected:
        return jsonify({'error': 'Not connected to server'})
        
    state['_temp_username'] = username # Hold temporarily until success
    
    state['network'].send_request({
        'action': 'LOGIN',
        'username': username,
        'password': password,
        'totp_token': totp_token
    })
    
    generate_keys_if_needed()
    return jsonify({'status': 'ok'})

@app.route('/api/start_chat', methods=['POST'])
def start_chat():
    data = request.json
    target = data.get('target')
    if not target:
        return jsonify({'error': 'Target required'})
        
    state['target_user'] = target
    state['messages'] = []
    
    state['network'].send_request({
        'action': 'GET_KEY',
        'target_user': target
    })
    return jsonify({'status': 'ok'})

@app.route('/api/send_message', methods=['POST'])
def send_message():
    data = request.json
    msg = data.get('message')
    if not msg or not state['target_user']:
        return jsonify({'error': 'Invalid message'})
        
    aes_key = state['aes_keys'].get(state['target_user'])
    if not aes_key:
        return jsonify({'error': 'No AES key established'})
        
    encrypted_bytes = CryptoUtils.encrypt_aes(aes_key, msg.encode('utf-8'))
    encrypted_b64 = base64.b64encode(encrypted_bytes).decode('utf-8')
    
    state['network'].send_request({
        'action': 'SEND_MSG',
        'target_user': state['target_user'],
        'encrypted_content': encrypted_b64
    })
    
    state['messages'].append({'sender': 'You', 'text': msg})
    return jsonify({'status': 'ok'})

@app.route('/api/logout', methods=['POST'])
def logout():
    state['username'] = None
    state['target_user'] = None
    state['chat_active'] = False
    state['messages'] = []
    state['aes_keys'] = {}
    state['contacts'] = set()
    return jsonify({'status': 'ok'})

if __name__ == '__main__':
    # Auto-connect on startup
    threading.Thread(target=state['network'].connect, daemon=True).start()
    app.run(port=5001, debug=False)

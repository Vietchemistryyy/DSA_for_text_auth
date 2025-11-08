"""
Flask Web Application cho DSA Digital Signature
"""
from flask import Flask, render_template, request, jsonify, send_file, session
from flask_cors import CORS
import sys
import os
import json
import base64
from pathlib import Path
from datetime import datetime
import secrets

# Thêm src vào path
# sys.path.insert(0, str(Path(__file__).parent / 'src'))

from src import KeyManager, DSASignature
from src.utils import format_hex

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)
CORS(app)

# Thư mục lưu trữ
UPLOAD_FOLDER = Path('uploads')
KEYS_FOLDER = Path('web_keys')
SIGNATURES_FOLDER = Path('web_signatures')

UPLOAD_FOLDER.mkdir(exist_ok=True)
KEYS_FOLDER.mkdir(exist_ok=True)
SIGNATURES_FOLDER.mkdir(exist_ok=True)

# Dictionary lưu key managers theo session
key_managers = {}


def get_key_manager():
    """Lấy key manager cho session hiện tại"""
    session_id = session.get('session_id')
    if not session_id:
        session_id = secrets.token_hex(16)
        session['session_id'] = session_id

    if session_id not in key_managers:
        key_managers[session_id] = KeyManager()

    return key_managers[session_id]


@app.route('/')
def index():
    """Trang chủ"""
    return render_template('index.html')


@app.route('/api/generate-keys', methods=['POST'])
def generate_keys():
    """API tạo cặp khóa mới"""
    try:
        km = get_key_manager()
        private_key, public_key = km.generate_keys(verbose=False)

        return jsonify({
            'success': True,
            'private_key': format_hex(private_key),
            'public_key': format_hex(public_key),
            'message': 'Đã tạo cặp khóa thành công!'
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@app.route('/api/sign-message', methods=['POST'])
def sign_message():
    """API ký văn bản"""
    try:
        data = request.json
        message = data.get('message')

        if not message:
            return jsonify({
                'success': False,
                'error': 'Vui lòng nhập văn bản!'
            }), 400

        km = get_key_manager()
        if not km.has_private_key():
            return jsonify({
                'success': False,
                'error': 'Chưa có private key! Hãy tạo khóa trước.'
            }), 400

        sig = DSASignature(km)
        signature = sig.sign_message(message)

        # Lưu vào file
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        sig_file = SIGNATURES_FOLDER / f'signature_{timestamp}.json'

        sig_data = {
            'message': message,
            'signature': {
                'r': format_hex(signature[0], prefix=False),
                's': format_hex(signature[1], prefix=False)
            },
            'public_key': format_hex(km.get_public_key(), prefix=False),
            'timestamp': datetime.now().isoformat()
        }

        with open(sig_file, 'w', encoding='utf-8') as f:
            json.dump(sig_data, f, indent=2, ensure_ascii=False)

        return jsonify({
            'success': True,
            'signature': sig_data['signature'],
            'message': 'Đã ký văn bản thành công!',
            'filename': sig_file.name
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@app.route('/api/verify-message', methods=['POST'])
def verify_message():
    """API xác thực chữ ký"""
    try:
        data = request.json
        message = data.get('message')
        signature_r = data.get('signature_r')
        signature_s = data.get('signature_s')
        public_key_hex = data.get('public_key')

        if not all([message, signature_r, signature_s, public_key_hex]):
            return jsonify({
                'success': False,
                'error': 'Thiếu thông tin!'
            }), 400

        # Convert hex to int
        r = int(signature_r.replace('0x', ''), 16)
        s = int(signature_s.replace('0x', ''), 16)
        public_key = int(public_key_hex.replace('0x', ''), 16)

        sig = DSASignature()
        is_valid = sig.verify_message(message, (r, s), public_key)

        return jsonify({
            'success': True,
            'valid': is_valid,
            'message': 'Chữ ký hợp lệ!' if is_valid else 'Chữ ký không hợp lệ!'
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@app.route('/api/sign-file', methods=['POST'])
def sign_file():
    """API ký file"""
    try:
        if 'file' not in request.files:
            return jsonify({
                'success': False,
                'error': 'Không có file!'
            }), 400

        file = request.files['file']
        if file.filename == '':
            return jsonify({
                'success': False,
                'error': 'Chưa chọn file!'
            }), 400

        km = get_key_manager()
        if not km.has_private_key():
            return jsonify({
                'success': False,
                'error': 'Chưa có private key!'
            }), 400

        # Lưu file
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"{timestamp}_{file.filename}"
        filepath = UPLOAD_FOLDER / filename
        file.save(filepath)

        # Ký file
        sig = DSASignature(km)
        sig_file = SIGNATURES_FOLDER / f"{filename}.sig"
        signature = sig.sign_file(str(filepath), str(sig_file))

        return jsonify({
            'success': True,
            'message': 'Đã ký file thành công!',
            'filename': filename,
            'signature_file': sig_file.name
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@app.route('/api/verify-file', methods=['POST'])
def verify_file():
    """API xác thực file"""
    try:
        if 'file' not in request.files or 'signature' not in request.files:
            return jsonify({
                'success': False,
                'error': 'Thiếu file hoặc chữ ký!'
            }), 400

        file = request.files['file']
        sig_file = request.files['signature']

        # Lưu file tạm
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        temp_file = UPLOAD_FOLDER / f"verify_{timestamp}_{file.filename}"
        temp_sig = UPLOAD_FOLDER / f"verify_{timestamp}_{sig_file.filename}"

        file.save(temp_file)
        sig_file.save(temp_sig)

        # Xác thực
        sig = DSASignature()
        is_valid = sig.verify_file(str(temp_file), str(temp_sig))

        # Xóa file tạm
        temp_file.unlink()
        temp_sig.unlink()

        return jsonify({
            'success': True,
            'valid': is_valid,
            'message': 'File hợp lệ!' if is_valid else 'File không hợp lệ!'
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@app.route('/api/export-keys', methods=['POST'])
def export_keys():
    """API export khóa"""
    try:
        data = request.json
        key_type = data.get('type', 'public')  # 'public' or 'private'

        km = get_key_manager()

        if key_type == 'private':
            if not km.has_private_key():
                return jsonify({
                    'success': False,
                    'error': 'Chưa có private key!'
                }), 400

            key_data = {
                'type': 'DSA_PRIVATE_KEY',
                'key': format_hex(km.get_private_key(), prefix=False),
                'timestamp': datetime.now().isoformat()
            }
            filename = 'private_key.json'
        else:
            if not km.has_public_key():
                return jsonify({
                    'success': False,
                    'error': 'Chưa có public key!'
                }), 400

            key_data = {
                'type': 'DSA_PUBLIC_KEY',
                'key': format_hex(km.get_public_key(), prefix=False),
                'timestamp': datetime.now().isoformat()
            }
            filename = 'public_key.json'

        # Lưu file
        key_file = KEYS_FOLDER / filename
        with open(key_file, 'w') as f:
            json.dump(key_data, f, indent=2)

        return jsonify({
            'success': True,
            'message': f'Đã export {key_type} key!',
            'data': json.dumps(key_data, indent=2)
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@app.route('/api/import-key', methods=['POST'])
def import_key():
    """API import khóa"""
    try:
        if 'file' not in request.files:
            return jsonify({
                'success': False,
                'error': 'Không có file!'
            }), 400

        file = request.files['file']
        key_data = json.load(file)

        km = get_key_manager()

        if key_data.get('type') == 'DSA_PRIVATE_KEY':
            private_key = int(key_data['key'], 16)
            km.set_keys(private_key=private_key)
            message = 'Đã import private key thành công!'
        elif key_data.get('type') == 'DSA_PUBLIC_KEY':
            public_key = int(key_data['key'], 16)
            km.set_keys(public_key=public_key)
            message = 'Đã import public key thành công!'
        else:
            return jsonify({
                'success': False,
                'error': 'File không hợp lệ!'
            }), 400

        return jsonify({
            'success': True,
            'message': message
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@app.route('/api/get-key-status', methods=['GET'])
def get_key_status():
    """API lấy trạng thái khóa"""
    try:
        km = get_key_manager()

        status = {
            'has_private': km.has_private_key(),
            'has_public': km.has_public_key()
        }

        if km.has_private_key():
            status['private_key'] = format_hex(km.get_private_key())[:20] + '...'

        if km.has_public_key():
            status['public_key'] = format_hex(km.get_public_key())[:20] + '...'

        return jsonify({
            'success': True,
            'status': status
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@app.route('/api/clear-keys', methods=['POST'])
def clear_keys():
    """API xóa khóa"""
    try:
        km = get_key_manager()
        km.clear_keys()

        return jsonify({
            'success': True,
            'message': 'Đã xóa tất cả khóa!'
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


if __name__ == '__main__':
    print("""
    ╔═══════════════════════════════════════════════════════════╗
    ║                                                           ║
    ║        🔐 DSA DIGITAL SIGNATURE WEB APPLICATION 🔐        ║
    ║                                                           ║
    ║              Server đang chạy tại: http://localhost:5000 ║
    ║                                                           ║
    ╚═══════════════════════════════════════════════════════════╝
    """)

    app.run(debug=True, host='0.0.0.0', port=5000)
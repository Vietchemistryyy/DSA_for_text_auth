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
SIGNATURES_FOLDER = Path('web_signatures')

UPLOAD_FOLDER.mkdir(exist_ok=True)
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
    """API xác thực chữ ký - BẮT BUỘC phải có public key trong session"""
    try:
        # Kiểm tra xem đã có public key chưa
        km = get_key_manager()
        if not km.has_public_key():
            return jsonify({
                'success': False,
                'error': 'Chưa có public key! Vui lòng import public key trước khi xác thực.'
            }), 400

        data = request.json
        message = data.get('message')
        signature_r = data.get('signature_r')
        signature_s = data.get('signature_s')

        if not all([message, signature_r, signature_s]):
            return jsonify({
                'success': False,
                'error': 'Thiếu thông tin!'
            }), 400

        # Convert hex to int
        r = int(signature_r.replace('0x', ''), 16)
        s = int(signature_s.replace('0x', ''), 16)

        # Lấy public key từ session (BẮT BUỘC)
        public_key = km.get_public_key()
        public_key_info = format_hex(public_key)[:20] + '...'

        sig = DSASignature(km)
        is_valid = sig.verify_message(message, (r, s), public_key)

        return jsonify({
            'success': True,
            'valid': is_valid,
            'message': 'Chữ ký hợp lệ!' if is_valid else 'Chữ ký không hợp lệ!',
            'public_key_used': public_key_info
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

        # Đọc nội dung file signature để trả về
        with open(sig_file, 'r') as f:
            sig_content = f.read()

        return jsonify({
            'success': True,
            'message': 'Đã ký file thành công!',
            'filename': filename,
            'signature_file': sig_file.name,
            'signature_content': sig_content  # Thêm nội dung để download
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@app.route('/api/verify-file', methods=['POST'])
def verify_file():
    """API xác thực file - BẮT BUỘC phải có public key trong session"""
    temp_file = None
    temp_sig = None
    
    try:
        # Kiểm tra xem đã có public key chưa
        km = get_key_manager()
        if not km.has_public_key():
            return jsonify({
                'success': False,
                'error': 'Chưa có public key! Vui lòng import public key trước khi xác thực.'
            }), 400

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

        # Lấy public key từ session (BẮT BUỘC)
        public_key = km.get_public_key()
        public_key_info = format_hex(public_key)[:20] + '...'
        
        # Đọc signature file để lấy thông tin
        try:
            with open(temp_sig, 'r') as f:
                sig_data = json.load(f)
            
            sig_r = int(sig_data['signature']['r'], 16)
            sig_s = int(sig_data['signature']['s'], 16)
        except (KeyError, ValueError) as e:
            print(f"ERROR parsing signature file: {e}")
            return jsonify({
                'success': False,
                'error': f'File chữ ký không hợp lệ! Định dạng sai hoặc thiếu thông tin.'
            }), 400
        
        # Lấy tham số DSA
        dsa_params = km.dsa.get_params()
        p, q, g = dsa_params['p'], dsa_params['q'], dsa_params['g']
        
        # Xác thực với public key từ session
        sig = DSASignature(km)
        is_valid = sig.verify_file(str(temp_file), str(temp_sig), public_key=public_key)
        
        # Phân tích lỗi chi tiết - xác định nguyên nhân CỤ THỂ
        error_hints = []
        error_type = None  # Loại lỗi chính
        
        if not is_valid:
            from src.utils import mod_inverse
            
            # 1. Kiểm tra chữ ký r có hợp lệ không
            if sig_r <= 0 or sig_r >= q:
                error_hints.append(f'❌ Chữ ký r = {sig_r} không hợp lệ (yêu cầu: 0 < r < q = {q})')
                error_type = 'INVALID_SIGNATURE_R'
            
            # 2. Kiểm tra chữ ký s có hợp lệ không
            if sig_s <= 0 or sig_s >= q:
                error_hints.append(f'❌ Chữ ký s = {sig_s} không hợp lệ (yêu cầu: 0 < s < q = {q})')
                error_type = 'INVALID_SIGNATURE_S'
            
            # 3. Kiểm tra public key có hợp lệ không
            if public_key <= 0 or public_key >= p:
                error_hints.append(f'❌ Public key y không hợp lệ (yêu cầu: 0 < y < p)')
                error_type = 'INVALID_PUBLIC_KEY'
            
            # 4. Nếu các tham số hợp lệ về mặt toán học, thực hiện xác thực thủ công để tìm nguyên nhân
            if not error_hints:
                try:
                    # Đọc và hash file hiện tại
                    with open(temp_file, 'rb') as f:
                        file_content = f.read()
                    
                    import hashlib
                    current_hash = int(hashlib.sha256(file_content).hexdigest(), 16)
                    
                    # Tính các giá trị xác thực
                    w = mod_inverse(sig_s, q)
                    u1 = (current_hash * w) % q
                    u2 = (sig_r * w) % q
                    g_u1 = pow(g, u1, p)
                    y_u2 = pow(public_key, u2, p)
                    v = ((g_u1 * y_u2) % p) % q
                    
                    # So sánh v và r
                    if v != sig_r:
                        # Kiểm tra xem có phải do public key sai không
                        # Nếu file signature có chứa public key gốc, so sánh
                        if 'public_key' in sig_data:
                            try:
                                original_pubkey = int(sig_data['public_key'], 16)
                                if original_pubkey != public_key:
                                    error_hints.append('Public key bạn đang dùng không khớp với public key của người ký.')
                                    error_hints.append('Bạn cần import đúng public key của người đã ký file này.')
                                    error_type = 'PUBLIC_KEY_MISMATCH'
                                else:
                                    # Public key khớp nhưng vẫn fail → file bị thay đổi
                                    error_hints.append('File hiện tại khác với file gốc khi được ký.')
                                    error_hints.append('Hash hiện tại không khớp với hash khi ký.')
                                    error_hints.append('File có thể đã bị chỉnh sửa hoặc bị hỏng trong quá trình truyền tải.')
                                    error_type = 'FILE_MODIFIED'
                            except:
                                error_hints.append('❌ KHÔNG THỂ XÁC ĐỊNH NGUYÊN NHÂN CHÍNH XÁC')
                                error_hints.append('   Có thể do: File bị thay đổi HOẶC Public key không đúng.')
                                error_type = 'UNKNOWN'
                        else:
                            # Không có public key trong signature để so sánh
                            error_hints.append('❌ XÁC THỰC THẤT BẠI - v ≠ r')
                            error_hints.append(f'   • Giá trị tính được v = {v}')
                            error_hints.append(f'   • Giá trị chữ ký r = {sig_r}')
                            error_hints.append('   Nguyên nhân có thể:')
                            error_hints.append('   1. File đã bị thay đổi sau khi ký')
                            error_hints.append('   2. Public key không đúng (không phải của người ký)')
                            error_hints.append('   3. File chữ ký không khớp với file này')
                            error_type = 'VERIFICATION_FAILED'
                except Exception as calc_error:
                    print(f"Error during manual verification: {calc_error}")
                    error_hints.append('❌ Lỗi trong quá trình xác thực')
                    error_hints.append(f'   Chi tiết: {str(calc_error)}')
                    error_type = 'CALCULATION_ERROR'

        return jsonify({
            'success': True,
            'valid': is_valid,
            'message': 'File hợp lệ!' if is_valid else 'File không hợp lệ!',
            'public_key_used': public_key_info,
            'error_hints': error_hints,
            'error_type': error_type
        })
        
    except Exception as e:
        import traceback
        print(f"ERROR in verify_file: {str(e)}")
        print(traceback.format_exc())
        return jsonify({
            'success': False,
            'error': f'Lỗi xác thực: {str(e)}'
        }), 500
        
    finally:
        # Đảm bảo luôn xóa file tạm dù có lỗi hay không
        try:
            if temp_file and temp_file.exists():
                temp_file.unlink()
            if temp_sig and temp_sig.exists():
                temp_sig.unlink()
        except Exception as cleanup_error:
            print(f"Lỗi khi xóa file tạm: {cleanup_error}")


@app.route('/api/export-keys', methods=['POST'])
def export_keys():
    """API export khóa - chỉ trả về data để download, không lưu vào server"""
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

        # Chỉ trả về data để frontend download, không lưu vào server
        return jsonify({
            'success': True,
            'message': f'Đã export {key_type} key!',
            'data': json.dumps(key_data, indent=2),
            'filename': filename
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
        key_preview = None

        if key_data.get('type') == 'DSA_PRIVATE_KEY':
            private_key = int(key_data['key'], 16)
            km.set_keys(private_key=private_key)
            # Tính public key từ private key
            public_key = pow(km.dsa.g, private_key, km.dsa.p)
            km.set_keys(public_key=public_key)
            message = 'Đã import private key thành công!'
            key_preview = format_hex(private_key)[:20] + '...'
        elif key_data.get('type') == 'DSA_PUBLIC_KEY':
            public_key = int(key_data['key'], 16)
            km.set_keys(public_key=public_key)
            message = 'Đã import public key thành công!'
            key_preview = format_hex(public_key)[:20] + '...'
        else:
            return jsonify({
                'success': False,
                'error': 'File không hợp lệ!'
            }), 400

        return jsonify({
            'success': True,
            'message': message,
            'key_preview': key_preview
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
        session_id = session.get('session_id')
        
        # Xóa KeyManager khỏi dictionary
        if session_id and session_id in key_managers:
            del key_managers[session_id]
        
        # Xóa session ID để tạo session mới
        session.pop('session_id', None)

        return jsonify({
            'success': True,
            'message': 'Đã xóa tất cả khóa và reset session!'
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@app.route('/api/demo-sign', methods=['POST'])
def demo_sign():
    """API demo ký với tham số thủ công - CHỈ ĐỂ DEMO, KHÔNG VALIDATE CHẶT"""
    try:
        data = request.json
        print(f"DEBUG: Received data: {data}")
        
        # Lấy tham số từ request - cho phép nhập số thập phân hoặc hex
        def parse_number(value):
            if not value:
                return None
            value = str(value).strip()
            
            # Nếu có prefix 0x thì chắc chắn là hex
            if value.startswith('0x') or value.startswith('0X'):
                return int(value, 16)
            
            # Thử parse decimal trước (ưu tiên)
            try:
                return int(value, 10)
            except:
                # Nếu không phải decimal, thử hex
                try:
                    return int(value, 16)
                except:
                    raise ValueError(f"Không thể parse giá trị: {value}")
        
        p = parse_number(data.get('p'))
        q = parse_number(data.get('q'))
        g = parse_number(data.get('g'))
        x = parse_number(data.get('x'))
        k = parse_number(data.get('k'))
        message = data.get('message', '')
        
        print(f"DEBUG: Parsed values - p={p}, q={q}, g={g}, x={x}, k={k}, message={message[:20] if message else 'empty'}")
        
        # Kiểm tra tham số cơ bản
        missing_params = []
        if p is None:
            missing_params.append('p')
        if q is None:
            missing_params.append('q')
        if g is None:
            missing_params.append('g')
        if x is None:
            missing_params.append('x')
        if not message:
            missing_params.append('message')
        
        if missing_params:
            error_msg = f'Thiếu tham số: {", ".join(missing_params)}. Vui lòng nhập đầy đủ.'
            print(f"DEBUG: Missing params error: {error_msg}")
            return jsonify({
                'success': False,
                'error': error_msg
            }), 400
        
        # DEMO MODE - Chỉ kiểm tra cơ bản, không validate chặt
        if x <= 0 or x >= q:
            error_msg = f'Private key x phải nằm trong khoảng (1, {q-1}). Bạn nhập x={x}, q={q}'
            print(f"DEBUG: x validation error: {error_msg}")
            return jsonify({
                'success': False,
                'error': error_msg
            }), 400
        
        # Tính public key
        y = pow(g, x, p)
        
        # Hash message
        from src.utils import hash_message
        message_hash = hash_message(message, 'sha256')
        
        # Nếu không có k, tạo ngẫu nhiên
        if not k:
            k = secrets.randbelow(q - 1) + 1
        else:
            if k <= 0 or k >= q:
                return jsonify({
                    'success': False,
                    'error': f'k phải nằm trong khoảng (1, {q-1}). Bạn nhập k={k}, q={q}'
                }), 400
        
        # BƯỚC KÝ
        # Tính r = (g^k mod p) mod q
        g_k_mod_p = pow(g, k, p)
        r = g_k_mod_p % q
        
        if r == 0:
            return jsonify({
                'success': False,
                'error': f'r = 0 (g^k mod p = {g_k_mod_p}), vui lòng chọn k khác!'
            }), 400
        
        # Tính s = k^(-1) * (H(m) + x*r) mod q
        from src.utils import mod_inverse
        k_inv = mod_inverse(k, q)
        x_r = (x * r) % q
        h_plus_xr = (message_hash + x_r) % q
        s = (k_inv * h_plus_xr) % q
        
        if s == 0:
            return jsonify({
                'success': False,
                'error': 's = 0, vui lòng chọn k khác!'
            }), 400
        
        # BƯỚC XÁC THỰC (để demo)
        # w = s^(-1) mod q
        w = mod_inverse(s, q)
        
        # u1 = H(m) * w mod q
        u1 = (message_hash * w) % q
        
        # u2 = r * w mod q
        u2 = (r * w) % q
        
        # v = ((g^u1 * y^u2) mod p) mod q
        g_u1 = pow(g, u1, p)
        y_u2 = pow(y, u2, p)
        g_u1_y_u2 = (g_u1 * y_u2) % p
        v = g_u1_y_u2 % q
        
        # Kiểm tra v == r
        is_valid = (v == r)
        
        # Trả về TẤT CẢ các giá trị tính toán
        return jsonify({
            'success': True,
            'message': 'Đã ký thành công!',
            'result': {
                # Tham số đầu vào
                'params': {
                    'p': str(p),
                    'q': str(q),
                    'g': str(g),
                    'x': str(x),
                    'k': str(k)
                },
                # Bước 1: Tính public key
                'step1': {
                    'y': str(y),
                    'formula': f'y = g^x mod p = {g}^{x} mod {p} = {y}'
                },
                # Bước 2: Hash message
                'step2': {
                    'message': message,
                    'hash': str(message_hash),
                    'formula': f'H(m) = SHA256("{message[:30]}...") = {message_hash}'
                },
                # Bước 3: Ký - Tính r
                'step3': {
                    'g_k_mod_p': str(g_k_mod_p),
                    'r': str(r),
                    'formula': f'r = (g^k mod p) mod q = ({g}^{k} mod {p}) mod {q} = {g_k_mod_p} mod {q} = {r}'
                },
                # Bước 4: Ký - Tính s
                'step4': {
                    'k_inv': str(k_inv),
                    'x_r': str(x_r),
                    'h_plus_xr': str(h_plus_xr),
                    's': str(s),
                    'formula': f's = k^(-1) * (H(m) + x*r) mod q = {k_inv} * ({message_hash} + {x}*{r}) mod {q} = {k_inv} * {h_plus_xr} mod {q} = {s}'
                },
                # Chữ ký
                'signature': {
                    'r': str(r),
                    's': str(s)
                },
                # Bước xác thực
                'verify': {
                    'w': str(w),
                    'w_formula': f'w = s^(-1) mod q = {s}^(-1) mod {q} = {w}',
                    'u1': str(u1),
                    'u1_formula': f'u1 = H(m) * w mod q = {message_hash} * {w} mod {q} = {u1}',
                    'u2': str(u2),
                    'u2_formula': f'u2 = r * w mod q = {r} * {w} mod {q} = {u2}',
                    'g_u1': str(g_u1),
                    'y_u2': str(y_u2),
                    'g_u1_y_u2': str(g_u1_y_u2),
                    'v': str(v),
                    'v_formula': f'v = ((g^u1 * y^u2) mod p) mod q = (({g}^{u1} * {y}^{u2}) mod {p}) mod {q} = ({g_u1} * {y_u2}) mod {p} mod {q} = {g_u1_y_u2} mod {q} = {v}',
                    'is_valid': is_valid,
                    'check': f'v == r? {v} == {r}? {is_valid}'
                }
            }
        })
        
    except ValueError as e:
        return jsonify({
            'success': False,
            'error': f'Lỗi giá trị: {str(e)}'
        }), 400
    except Exception as e:
        return jsonify({
            'success': False,
            'error': f'Lỗi: {str(e)}'
        }), 500


@app.route('/api/demo-sign-file', methods=['POST'])
def demo_sign_file():
    """API demo ký file với tham số thủ công"""
    try:
        # Hàm parse số (ưu tiên decimal)
        def parse_number(value):
            if not value:
                return None
            value = str(value).strip()
            if value.startswith('0x') or value.startswith('0X'):
                return int(value, 16)
            try:
                return int(value, 10)
            except:
                try:
                    return int(value, 16)
                except:
                    raise ValueError(f"Không thể parse giá trị: {value}")
        
        # Lấy tham số từ form
        p = parse_number(request.form.get('p'))
        q = parse_number(request.form.get('q'))
        g = parse_number(request.form.get('g'))
        x = parse_number(request.form.get('x'))
        k = parse_number(request.form.get('k'))
        
        # Lấy file
        if 'file' not in request.files:
            return jsonify({
                'success': False,
                'error': 'Thiếu file! Vui lòng chọn file cần ký.'
            }), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({
                'success': False,
                'error': 'Chưa chọn file! Vui lòng chọn file cần ký.'
            }), 400
        
        # Đọc nội dung file
        content = file.read().decode('utf-8')
        
        # Kiểm tra từng tham số cụ thể
        missing_params = []
        if not p:
            missing_params.append('p')
        if not q:
            missing_params.append('q')
        if not g:
            missing_params.append('g')
        if not x:
            missing_params.append('x')
        
        if missing_params:
            return jsonify({
                'success': False,
                'error': f'Thiếu tham số: {", ".join(missing_params)}. Vui lòng nhập đầy đủ.'
            }), 400
        
        # DEMO MODE - Chỉ kiểm tra cơ bản
        if x <= 0 or x >= q:
            return jsonify({
                'success': False,
                'error': f'Private key x phải nằm trong khoảng (1, {q-1}). Bạn nhập x={x}, q={q}'
            }), 400
        
        # Tính public key
        y = pow(g, x, p)
        
        # Hash message
        from src.utils import hash_message, mod_inverse
        message_hash = hash_message(content, 'sha256')
        
        # Nếu không có k, tạo ngẫu nhiên
        if not k:
            k = secrets.randbelow(q - 1) + 1
        else:
            if k <= 0 or k >= q:
                return jsonify({
                    'success': False,
                    'error': f'k phải nằm trong khoảng (1, {q-1}). Bạn nhập k={k}, q={q}'
                }), 400
        
        # BƯỚC KÝ
        g_k_mod_p = pow(g, k, p)
        r = g_k_mod_p % q
        
        if r == 0:
            return jsonify({
                'success': False,
                'error': f'r = 0 (g^k mod p = {g_k_mod_p}), vui lòng chọn k khác!'
            }), 400
        
        k_inv = mod_inverse(k, q)
        x_r = (x * r) % q
        h_plus_xr = (message_hash + x_r) % q
        s = (k_inv * h_plus_xr) % q
        
        if s == 0:
            return jsonify({
                'success': False,
                'error': 's = 0, vui lòng chọn k khác!'
            }), 400
        
        # BƯỚC XÁC THỰC
        w = mod_inverse(s, q)
        u1 = (message_hash * w) % q
        u2 = (r * w) % q
        g_u1 = pow(g, u1, p)
        y_u2 = pow(y, u2, p)
        g_u1_y_u2 = (g_u1 * y_u2) % p
        v = g_u1_y_u2 % q
        is_valid = (v == r)
        
        # Trả về TẤT CẢ các giá trị
        return jsonify({
            'success': True,
            'message': 'Đã ký file thành công!',
            'filename': file.filename,
            'file_content': content[:200] + ('...' if len(content) > 200 else ''),
            'result': {
                'params': {
                    'p': str(p),
                    'q': str(q),
                    'g': str(g),
                    'x': str(x),
                    'k': str(k)
                },
                'step1': {
                    'y': str(y),
                    'formula': f'y = g^x mod p = {g}^{x} mod {p} = {y}'
                },
                'step2': {
                    'message': content[:50] + ('...' if len(content) > 50 else ''),
                    'hash': str(message_hash),
                    'formula': f'H(m) = SHA256(file_content) = {message_hash}'
                },
                'step3': {
                    'g_k_mod_p': str(g_k_mod_p),
                    'r': str(r),
                    'formula': f'r = (g^k mod p) mod q = ({g}^{k} mod {p}) mod {q} = {g_k_mod_p} mod {q} = {r}'
                },
                'step4': {
                    'k_inv': str(k_inv),
                    'x_r': str(x_r),
                    'h_plus_xr': str(h_plus_xr),
                    's': str(s),
                    'formula': f's = k^(-1) * (H(m) + x*r) mod q = {k_inv} * ({message_hash} + {x}*{r}) mod {q} = {k_inv} * {h_plus_xr} mod {q} = {s}'
                },
                'signature': {
                    'r': str(r),
                    's': str(s)
                },
                'verify': {
                    'w': str(w),
                    'w_formula': f'w = s^(-1) mod q = {s}^(-1) mod {q} = {w}',
                    'u1': str(u1),
                    'u1_formula': f'u1 = H(m) * w mod q = {message_hash} * {w} mod {q} = {u1}',
                    'u2': str(u2),
                    'u2_formula': f'u2 = r * w mod q = {r} * {w} mod {q} = {u2}',
                    'g_u1': str(g_u1),
                    'y_u2': str(y_u2),
                    'g_u1_y_u2': str(g_u1_y_u2),
                    'v': str(v),
                    'v_formula': f'v = ((g^u1 * y^u2) mod p) mod q = (({g}^{u1} * {y}^{u2}) mod {p}) mod {q} = ({g_u1} * {y_u2}) mod {p} mod {q} = {g_u1_y_u2} mod {q} = {v}',
                    'is_valid': is_valid,
                    'check': f'v == r? {v} == {r}? {is_valid}'
                }
            }
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': f'Lỗi: {str(e)}'
        }), 500


@app.route('/api/demo-verify', methods=['POST'])
def demo_verify():
    """API demo xác thực với tham số thủ công"""
    try:
        data = request.json
        
        print(f"\n=== DEBUG DEMO-VERIFY ===")
        print(f"Received data: {data}")
        
        # Parse số
        def parse_number(value):
            if not value:
                return None
            value = str(value).strip()
            if value.startswith('0x') or value.startswith('0X'):
                return int(value, 16)
            try:
                return int(value, 10)
            except:
                try:
                    return int(value, 16)
                except:
                    raise ValueError(f"Không thể parse giá trị: {value}")
        
        p = parse_number(data.get('p'))
        q = parse_number(data.get('q'))
        g = parse_number(data.get('g'))
        y = parse_number(data.get('y'))
        r = parse_number(data.get('r'))
        s = parse_number(data.get('s'))
        message = data.get('message', '')
        
        print(f"Message received: '{message}'")
        print(f"Message length: {len(message)}")
        
        # Kiểm tra từng tham số cụ thể
        missing_params = []
        if p is None:
            missing_params.append('p')
        if q is None:
            missing_params.append('q')
        if g is None:
            missing_params.append('g')
        if y is None:
            missing_params.append('y')
        if r is None:
            missing_params.append('r')
        if s is None:
            missing_params.append('s')
        if not message:
            missing_params.append('message')
        
        if missing_params:
            error_msg = f'Thiếu tham số: {", ".join(missing_params)}. Vui lòng nhập đầy đủ.'
            return jsonify({
                'success': False,
                'error': error_msg
            }), 400
        
        # Hash message
        from src.utils import hash_message, mod_inverse
        message_hash = hash_message(message, 'sha256')
        
        print(f"Message hash: {message_hash}")
        
        # BƯỚC XÁC THỰC
        # Bước 1: Hash message
        # Bước 2: w = s^(-1) mod q
        w = mod_inverse(s, q)
        
        # Bước 3: u1 = H(m) * w mod q
        u1 = (message_hash * w) % q
        
        # Bước 4: u2 = r * w mod q
        u2 = (r * w) % q
        
        # Bước 5: v = ((g^u1 * y^u2) mod p) mod q
        g_u1 = pow(g, u1, p)
        y_u2 = pow(y, u2, p)
        g_u1_y_u2 = (g_u1 * y_u2) % p
        v = g_u1_y_u2 % q
        
        # Kiểm tra v == r
        is_valid = (v == r)
        
        print(f"Verification result: v={v}, r={r}, is_valid={is_valid}")
        print(f"=== END DEBUG ===\n")
        
        # Phân tích lỗi chi tiết - XÁC ĐỊNH CHÍNH XÁC nguyên nhân
        error_hints = []
        error_type = None
        collision_warning = None
        
        # Kiểm tra collision với tham số nhỏ
        original_message = data.get('original_message', '')
        if is_valid and original_message and message != original_message:
            # Message đã thay đổi nhưng xác thực vẫn hợp lệ -> COLLISION!
            original_hash = hash_message(original_message, 'sha256')
            original_u1 = (original_hash * w) % q
            
            print(f"COLLISION DETECTED!")
            print(f"Original message: '{original_message}'")
            print(f"Current message: '{message}'")
            print(f"Original hash mod q = {original_hash % q}")
            print(f"Current hash mod q = {message_hash % q}")
            
            # Đây là collision do tham số nhỏ
            collision_warning = {
                'detected': True,
                'original_message': original_message,
                'current_message': message
            }
            # Đánh dấu là không thực sự hợp lệ do collision
            is_valid = False
            error_type = 'MESSAGE_CHANGED'
            error_hints.append('VĂN BẢN ĐÃ BỊ THAY ĐỔI!')
            error_hints.append(f'Văn bản gốc: "{original_message}"')
            error_hints.append(f'Văn bản hiện tại: "{message}"')
            error_hints.append(f'Lưu ý: Do sử dụng tham số demo nhỏ (q={q}), kết quả toán học có thể trùng khớp dù văn bản khác nhau.')
        
        if not is_valid:
            # Kiểm tra signature có hợp lệ về mặt toán học không
            if r <= 0 or r >= q:
                error_hints.append(f'❌ Chữ ký r = {r} không hợp lệ (yêu cầu: 0 < r < q = {q})')
                error_type = 'INVALID_R'
            if s <= 0 or s >= q:
                error_hints.append(f'❌ Chữ ký s = {s} không hợp lệ (yêu cầu: 0 < s < q = {q})')
                error_type = 'INVALID_S'
            
            # Kiểm tra public key
            if y <= 0 or y >= p:
                error_hints.append(f'❌ Public key y = {y} không hợp lệ (yêu cầu: 0 < y < p = {p})')
                error_type = 'INVALID_Y'
            
            # Lấy giá trị gốc từ phần ký (nếu có)
            original_p = parse_number(data.get('original_p'))
            original_q = parse_number(data.get('original_q'))
            original_g = parse_number(data.get('original_g'))
            original_y = parse_number(data.get('original_y'))
            original_r = parse_number(data.get('original_r'))
            original_s = parse_number(data.get('original_s'))
            original_message = data.get('original_message', '')
            
            # Nếu có giá trị gốc, so sánh chính xác
            if not error_hints:
                if original_p is not None or original_q is not None or original_g is not None:
                    # Có thông tin gốc - so sánh chính xác
                    changed_params = []
                    
                    if original_p is not None and p != original_p:
                        changed_params.append(f'p: {original_p} → {p}')
                        error_type = 'PARAM_P_CHANGED'
                    if original_q is not None and q != original_q:
                        changed_params.append(f'q: {original_q} → {q}')
                        error_type = 'PARAM_Q_CHANGED'
                    if original_g is not None and g != original_g:
                        changed_params.append(f'g: {original_g} → {g}')
                        error_type = 'PARAM_G_CHANGED'
                    if original_y is not None and y != original_y:
                        changed_params.append(f'y: {original_y} → {y}')
                        error_type = 'PUBLIC_KEY_CHANGED'
                    if original_r is not None and r != original_r:
                        changed_params.append(f'r: {original_r} → {r}')
                        error_type = 'SIGNATURE_R_CHANGED'
                    if original_s is not None and s != original_s:
                        changed_params.append(f's: {original_s} → {s}')
                        error_type = 'SIGNATURE_S_CHANGED'
                    if original_message and message != original_message:
                        error_type = 'MESSAGE_CHANGED'
                        if len(original_message) != len(message):
                            error_hints.append(f'❌ VĂN BẢN ĐÃ BỊ THAY ĐỔI!')
                            error_hints.append(f'   • Độ dài gốc: {len(original_message)} ký tự')
                            error_hints.append(f'   • Độ dài hiện tại: {len(message)} ký tự')
                        else:
                            # Tìm vị trí khác biệt
                            for i, (c1, c2) in enumerate(zip(original_message, message)):
                                if c1 != c2:
                                    error_hints.append(f'❌ VĂN BẢN ĐÃ BỊ THAY ĐỔI tại vị trí {i+1}!')
                                    error_hints.append(f'   • Ký tự gốc: "{c1}"')
                                    error_hints.append(f'   • Ký tự hiện tại: "{c2}"')
                                    break
                    
                    if changed_params:
                        error_hints.append('❌ GIÁ TRỊ ĐÃ BỊ THAY ĐỔI so với phần ký:')
                        for param in changed_params:
                            error_hints.append(f'   • {param}')
                    
                    if not error_hints:
                        # Không tìm thấy thay đổi nhưng vẫn fail - lỗi logic
                        error_hints.append('❌ XÁC THỰC THẤT BẠI - v ≠ r')
                        error_hints.append(f'   Các tham số khớp với phần ký nhưng kết quả sai.')
                        error_hints.append(f'   Có thể có lỗi trong quá trình tính toán.')
                        error_type = 'CALCULATION_ERROR'
                else:
                    # Không có thông tin gốc - liệt kê các nguyên nhân có thể
                    error_hints.append('❌ XÁC THỰC THẤT BẠI - v ≠ r')
                    error_hints.append('   Nguyên nhân có thể (không xác định được chính xác vì thiếu dữ liệu gốc):')
                    error_hints.append('   1. Văn bản đã bị thay đổi sau khi ký')
                    error_hints.append('   2. Chữ ký (r, s) không khớp với văn bản')  
                    error_hints.append('   3. Public key y không đúng')
                    error_hints.append('   4. Tham số DSA (p, q, g) không đúng')
                    error_type = 'UNKNOWN'
        
        return jsonify({
            'success': True,
            'result': {
                'params': {
                    'p': str(p),
                    'q': str(q),
                    'g': str(g),
                    'y': str(y)
                },
                'signature': {
                    'r': str(r),
                    's': str(s)
                },
                'step1': {
                    'hash': str(message_hash),
                    'formula': f'H(m) = SHA256("{message[:30]}...") = {message_hash}'
                },
                'step2': {
                    'w': str(w),
                    'formula': f'w = s^(-1) mod q = {s}^(-1) mod {q} = {w}'
                },
                'step3': {
                    'u1': str(u1),
                    'formula': f'u1 = H(m) * w mod q = {message_hash} * {w} mod {q} = {u1}'
                },
                'step4': {
                    'u2': str(u2),
                    'formula': f'u2 = r * w mod q = {r} * {w} mod {q} = {u2}'
                },
                'step5': {
                    'g_u1': str(g_u1),
                    'y_u2': str(y_u2),
                    'g_u1_y_u2': str(g_u1_y_u2),
                    'v': str(v)
                },
                'is_valid': is_valid,
                'error_hints': error_hints,
                'error_type': error_type,
                'collision_warning': collision_warning
            }
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': f'Lỗi: {str(e)}'
        }), 500


if __name__ == '__main__':
    print("Server đang chạy tại: http://localhost:5000")
    app.run(debug=True, host='0.0.0.0', port=5000)

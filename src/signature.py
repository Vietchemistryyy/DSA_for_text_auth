"""
DSA Signature - Ký và xác thực văn bản
"""
import json
from typing import Tuple, Optional
from pathlib import Path
from .dsa_core import DSACore
from .key_manager import KeyManager
from .utils import hash_message, format_hex


class DSASignature:
    """
    Lớp xử lý ký và xác thực chữ ký DSA
    """

    def __init__(self, key_manager: KeyManager = None):
        """
        Khởi tạo DSA Signature

        Args:
            key_manager: KeyManager instance (tạo mới nếu None)
        """
        self.key_manager = key_manager if key_manager else KeyManager()
        self.dsa = self.key_manager.dsa

    def sign_message(self, message: str, hash_algorithm: str = 'sha256') -> Tuple[int, int]:
        """
        Ký văn bản

        Args:
            message: Văn bản cần ký
            hash_algorithm: Thuật toán hash (mặc định sha256)

        Returns:
            Tuple[int, int]: Chữ ký (r, s)

        Raises:
            ValueError: Nếu chưa có private key
        """
        if not self.key_manager.has_private_key():
            raise ValueError("Chưa có private key! Hãy tạo hoặc tải private key trước.")

        # Hash message
        message_hash = hash_message(message, hash_algorithm)

        # Ký
        private_key = self.key_manager.get_private_key()
        signature = self.dsa.sign(message_hash, private_key)

        print(f"✅ Đã ký văn bản thành công!")
        print(f"   Message: {message[:50]}{'...' if len(message) > 50 else ''}")
        print(f"   Signature (r): {format_hex(signature[0])}")
        print(f"   Signature (s): {format_hex(signature[1])}")

        return signature

    def verify_message(self, message: str, signature: Tuple[int, int],
                       public_key: int = None, hash_algorithm: str = 'sha256') -> bool:
        """
        Xác thực chữ ký

        Args:
            message: Văn bản gốc
            signature: Chữ ký (r, s)
            public_key: Public key (dùng key trong manager nếu None)
            hash_algorithm: Thuật toán hash

        Returns:
            bool: True nếu chữ ký hợp lệ

        Raises:
            ValueError: Nếu không có public key
        """
        if public_key is None:
            if not self.key_manager.has_public_key():
                raise ValueError("Chưa có public key! Hãy cung cấp public key.")
            public_key = self.key_manager.get_public_key()

        # Hash message
        message_hash = hash_message(message, hash_algorithm)

        # Xác thực
        is_valid = self.dsa.verify(message_hash, signature, public_key)

        if is_valid:
            print(f"✅ Chữ ký HỢP LỆ!")
            print(f"   Văn bản chưa bị thay đổi và chữ ký đúng.")
        else:
            print(f"❌ Chữ ký KHÔNG HỢP LỆ!")
            print(f"   Văn bản có thể đã bị thay đổi hoặc chữ ký sai.")

        return is_valid

    def sign_file(self, input_filepath: str, output_filepath: str = None,
                  hash_algorithm: str = 'sha256') -> Tuple[int, int]:
        """
        Ký file văn bản

        Args:
            input_filepath: Đường dẫn file văn bản
            output_filepath: Đường dẫn lưu chữ ký (mặc định: input_filepath + .sig)
            hash_algorithm: Thuật toán hash

        Returns:
            Tuple[int, int]: Chữ ký (r, s)
        """
        # Đọc nội dung file
        with open(input_filepath, 'r', encoding='utf-8') as f:
            message = f.read()

        # Ký
        signature = self.sign_message(message, hash_algorithm)

        # Tạo file chữ ký
        if output_filepath is None:
            output_filepath = input_filepath + '.sig'

        signature_data = {
            'signature': {
                'r': format_hex(signature[0], prefix=False),
                's': format_hex(signature[1], prefix=False)
            },
            'algorithm': hash_algorithm,
            'original_file': input_filepath
        }

        Path(output_filepath).parent.mkdir(parents=True, exist_ok=True)

        with open(output_filepath, 'w') as f:
            json.dump(signature_data, f, indent=2)

        print(f"💾 Đã lưu chữ ký vào: {output_filepath}")

        return signature

    def verify_file(self, input_filepath: str, signature_filepath: str,
                    public_key: int = None) -> bool:
        """
        Xác thực chữ ký của file

        Args:
            input_filepath: Đường dẫn file văn bản
            signature_filepath: Đường dẫn file chữ ký
            public_key: Public key (dùng key trong manager nếu None)

        Returns:
            bool: True nếu chữ ký hợp lệ
        """
        # Đọc văn bản
        with open(input_filepath, 'r', encoding='utf-8') as f:
            message = f.read()

        # Đọc chữ ký
        with open(signature_filepath, 'r') as f:
            signature_data = json.load(f)

        r = int(signature_data['signature']['r'], 16)
        s = int(signature_data['signature']['s'], 16)
        signature = (r, s)

        hash_algorithm = signature_data.get('algorithm', 'sha256')

        # Xác thực
        return self.verify_message(message, signature, public_key, hash_algorithm)

    def create_signature_package(self, message: str, output_filepath: str,
                                 hash_algorithm: str = 'sha256'):
        """
        Tạo gói chữ ký hoàn chỉnh (message + signature + public key)

        Args:
            message: Văn bản cần ký
            output_filepath: Đường dẫn lưu gói
            hash_algorithm: Thuật toán hash
        """
        if not self.key_manager.has_public_key():
            raise ValueError("Chưa có public key!")

        # Ký message
        signature = self.sign_message(message, hash_algorithm)

        # Tạo package
        package = {
            'message': message,
            'signature': {
                'r': format_hex(signature[0], prefix=False),
                's': format_hex(signature[1], prefix=False)
            },
            'public_key': format_hex(self.key_manager.get_public_key(), prefix=False),
            'algorithm': hash_algorithm,
            'params': {
                'p': format_hex(self.dsa.p, prefix=False),
                'q': format_hex(self.dsa.q, prefix=False),
                'g': format_hex(self.dsa.g, prefix=False)
            }
        }

        Path(output_filepath).parent.mkdir(parents=True, exist_ok=True)

        with open(output_filepath, 'w') as f:
            json.dump(package, f, indent=2, ensure_ascii=False)

        print(f"📦 Đã tạo gói chữ ký hoàn chỉnh: {output_filepath}")

    def verify_signature_package(self, package_filepath: str) -> bool:
        """
        Xác thực gói chữ ký hoàn chỉnh

        Args:
            package_filepath: Đường dẫn gói chữ ký

        Returns:
            bool: True nếu chữ ký hợp lệ
        """
        # Đọc package
        with open(package_filepath, 'r') as f:
            package = json.load(f)

        message = package['message']
        r = int(package['signature']['r'], 16)
        s = int(package['signature']['s'], 16)
        signature = (r, s)
        public_key = int(package['public_key'], 16)
        hash_algorithm = package.get('algorithm', 'sha256')

        # Tạo DSA với tham số từ package
        if 'params' in package:
            params = package['params']
            dsa_temp = DSACore(
                p=int(params['p'], 16),
                q=int(params['q'], 16),
                g=int(params['g'], 16)
            )
            self.dsa = dsa_temp

        # Xác thực
        print(f"\n📦 Đang xác thực gói chữ ký từ: {package_filepath}")
        return self.verify_message(message, signature, public_key, hash_algorithm)

    def batch_sign_files(self, filepaths: list, output_dir: str = 'signatures',
                         hash_algorithm: str = 'sha256'):
        """
        Ký hàng loạt file

        Args:
            filepaths: Danh sách đường dẫn file
            output_dir: Thư mục lưu chữ ký
            hash_algorithm: Thuật toán hash
        """
        Path(output_dir).mkdir(parents=True, exist_ok=True)

        results = []
        for filepath in filepaths:
            try:
                filename = Path(filepath).name
                output_path = Path(output_dir) / f"{filename}.sig"
                signature = self.sign_file(filepath, str(output_path), hash_algorithm)
                results.append((filepath, 'SUCCESS', signature))
            except Exception as e:
                results.append((filepath, 'FAILED', str(e)))

        # In báo cáo
        print(f"\n📊 Báo cáo ký hàng loạt:")
        print(f"{'=' * 60}")
        for filepath, status, info in results:
            print(f"{Path(filepath).name}: {status}")
        print(f"{'=' * 60}")
        print(f"Thành công: {sum(1 for _, s, _ in results if s == 'SUCCESS')}/{len(results)}")

    def __str__(self) -> str:
        """String representation"""
        return f"DSASignature (KeyManager: {self.key_manager})"

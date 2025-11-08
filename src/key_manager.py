"""
Key Manager - Quản lý khóa DSA
"""
import json
import os
from typing import Tuple, Optional
from pathlib import Path
from .dsa_core import DSACore
from .utils import format_hex, print_key_info


class KeyManager:
    """
    Quản lý việc tạo, lưu trữ và tải khóa DSA
    """

    def __init__(self, dsa_core: DSACore = None):
        """
        Khởi tạo Key Manager

        Args:
            dsa_core: Instance của DSACore (tạo mới nếu None)
        """
        self.dsa = dsa_core if dsa_core is not None else DSACore()
        self.private_key: Optional[int] = None
        self.public_key: Optional[int] = None

    def generate_keys(self, verbose: bool = True) -> Tuple[int, int]:
        """
        Tạo cặp khóa mới

        Args:
            verbose: Có in thông tin ra console không

        Returns:
            Tuple[int, int]: (private_key, public_key)
        """
        self.private_key, self.public_key = self.dsa.generate_key_pair()

        if verbose:
            print("\n🔐 Đã tạo cặp khóa DSA thành công!")
            print_key_info("Private", self.private_key)
            print_key_info("Public", self.public_key)

        return self.private_key, self.public_key

    def set_keys(self, private_key: int = None, public_key: int = None):
        """
        Đặt khóa thủ công

        Args:
            private_key: Private key (nếu có)
            public_key: Public key (nếu có)
        """
        if private_key is not None:
            if not (1 <= private_key < self.dsa.q):
                raise ValueError("Private key không hợp lệ")
            self.private_key = private_key

        if public_key is not None:
            self.public_key = public_key

    def save_private_key(self, filepath: str, password: str = None):
        """
        Lưu private key vào file

        Args:
            filepath: Đường dẫn file
            password: Mật khẩu mã hóa (tùy chọn)

        Raises:
            ValueError: Nếu chưa có private key
        """
        if self.private_key is None:
            raise ValueError("Chưa có private key để lưu!")

        key_data = {
            'type': 'DSA_PRIVATE_KEY',
            'key': format_hex(self.private_key, prefix=False),
            'params': {
                'p': format_hex(self.dsa.p, prefix=False),
                'q': format_hex(self.dsa.q, prefix=False),
                'g': format_hex(self.dsa.g, prefix=False)
            }
        }

        # TODO: Thêm mã hóa với password nếu cần
        if password:
            print("⚠️  Cảnh báo: Mã hóa với password chưa được triển khai")

        Path(filepath).parent.mkdir(parents=True, exist_ok=True)

        with open(filepath, 'w') as f:
            json.dump(key_data, f, indent=2)

        # Đặt quyền chỉ đọc cho owner
        os.chmod(filepath, 0o600)
        print(f"✅ Đã lưu private key vào: {filepath}")

    def save_public_key(self, filepath: str):
        """
        Lưu public key vào file

        Args:
            filepath: Đường dẫn file

        Raises:
            ValueError: Nếu chưa có public key
        """
        if self.public_key is None:
            raise ValueError("Chưa có public key để lưu!")

        key_data = {
            'type': 'DSA_PUBLIC_KEY',
            'key': format_hex(self.public_key, prefix=False),
            'params': {
                'p': format_hex(self.dsa.p, prefix=False),
                'q': format_hex(self.dsa.q, prefix=False),
                'g': format_hex(self.dsa.g, prefix=False)
            }
        }

        Path(filepath).parent.mkdir(parents=True, exist_ok=True)

        with open(filepath, 'w') as f:
            json.dump(key_data, f, indent=2)

        print(f"✅ Đã lưu public key vào: {filepath}")

    def load_private_key(self, filepath: str, password: str = None) -> int:
        """
        Tải private key từ file

        Args:
            filepath: Đường dẫn file
            password: Mật khẩu giải mã (tùy chọn)

        Returns:
            int: Private key

        Raises:
            FileNotFoundError: Nếu file không tồn tại
            ValueError: Nếu file không hợp lệ
        """
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"Không tìm thấy file: {filepath}")

        with open(filepath, 'r') as f:
            key_data = json.load(f)

        if key_data.get('type') != 'DSA_PRIVATE_KEY':
            raise ValueError("File không phải private key DSA!")

        # TODO: Giải mã với password nếu cần
        if password:
            print("⚠️  Cảnh báo: Giải mã với password chưa được triển khai")

        self.private_key = int(key_data['key'], 16)

        # Cập nhật tham số DSA nếu có
        if 'params' in key_data:
            params = key_data['params']
            self.dsa = DSACore(
                p=int(params['p'], 16),
                q=int(params['q'], 16),
                g=int(params['g'], 16)
            )

        print(f"✅ Đã tải private key từ: {filepath}")
        return self.private_key

    def load_public_key(self, filepath: str) -> int:
        """
        Tải public key từ file

        Args:
            filepath: Đường dẫn file

        Returns:
            int: Public key

        Raises:
            FileNotFoundError: Nếu file không tồn tại
            ValueError: Nếu file không hợp lệ
        """
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"Không tìm thấy file: {filepath}")

        with open(filepath, 'r') as f:
            key_data = json.load(f)

        if key_data.get('type') != 'DSA_PUBLIC_KEY':
            raise ValueError("File không phải public key DSA!")

        self.public_key = int(key_data['key'], 16)

        # Cập nhật tham số DSA nếu có
        if 'params' in key_data:
            params = key_data['params']
            self.dsa = DSACore(
                p=int(params['p'], 16),
                q=int(params['q'], 16),
                g=int(params['g'], 16)
            )

        print(f"✅ Đã tải public key từ: {filepath}")
        return self.public_key

    def export_keys(self) -> dict:
        """
        Export khóa dưới dạng dictionary

        Returns:
            dict: Dictionary chứa private và public key
        """
        return {
            'private_key': format_hex(self.private_key) if self.private_key else None,
            'public_key': format_hex(self.public_key) if self.public_key else None,
            'params': self.dsa.get_params()
        }

    def get_private_key(self) -> Optional[int]:
        """Lấy private key hiện tại"""
        return self.private_key

    def get_public_key(self) -> Optional[int]:
        """Lấy public key hiện tại"""
        return self.public_key

    def has_private_key(self) -> bool:
        """Kiểm tra có private key chưa"""
        return self.private_key is not None

    def has_public_key(self) -> bool:
        """Kiểm tra có public key chưa"""
        return self.public_key is not None

    def clear_keys(self):
        """Xóa tất cả khóa trong bộ nhớ"""
        self.private_key = None
        self.public_key = None
        print("🗑️  Đã xóa tất cả khóa khỏi bộ nhớ")

    def __str__(self) -> str:
        """String representation"""
        status = []
        if self.has_private_key():
            status.append("Private Key: ✓")
        else:
            status.append("Private Key: ✗")

        if self.has_public_key():
            status.append("Public Key: ✓")
        else:
            status.append("Public Key: ✗")

        return f"KeyManager ({', '.join(status)})"
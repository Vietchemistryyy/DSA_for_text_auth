"""
Unit tests cho DSA Core
"""
import pytest
import sys
from pathlib import Path

# Thêm src vào path
# sys.path.insert(0, str(Path(__file__).parent.parent / 'src'))

from src.dsa_core import DSACore
from src.utils import hash_message


class TestDSACore:
    """Test cases cho DSACore"""

    def setup_method(self):
        """Setup trước mỗi test"""
        self.dsa = DSACore()

    def test_init_default_params(self):
        """Test khởi tạo với tham số mặc định"""
        assert self.dsa.p == DSACore.DEFAULT_P
        assert self.dsa.q == DSACore.DEFAULT_Q
        assert self.dsa.g == DSACore.DEFAULT_G

    def test_init_custom_params(self):
        """Test khởi tạo với tham số tùy chỉnh"""
        p = 23
        q = 11
        g = 2

        # Tham số này không hợp lệ, nên sẽ raise ValueError
        with pytest.raises(ValueError):
            DSACore(p=p, q=q, g=g)

    def test_generate_private_key(self):
        """Test tạo private key"""
        private_key = self.dsa.generate_private_key()

        assert isinstance(private_key, int)
        assert 1 <= private_key < self.dsa.q

    def test_generate_public_key(self):
        """Test tạo public key từ private key"""
        private_key = self.dsa.generate_private_key()
        public_key = self.dsa.generate_public_key(private_key)

        assert isinstance(public_key, int)
        assert 1 <= public_key < self.dsa.p

        # Kiểm tra y = g^x mod p
        expected = pow(self.dsa.g, private_key, self.dsa.p)
        assert public_key == expected

    def test_generate_key_pair(self):
        """Test tạo cặp khóa"""
        private_key, public_key = self.dsa.generate_key_pair()

        assert isinstance(private_key, int)
        assert isinstance(public_key, int)
        assert 1 <= private_key < self.dsa.q
        assert 1 <= public_key < self.dsa.p

    def test_sign_and_verify_valid(self):
        """Test ký và xác thực chữ ký hợp lệ"""
        message = "Hello, DSA!"
        message_hash = hash_message(message)

        private_key, public_key = self.dsa.generate_key_pair()

        # Ký
        signature = self.dsa.sign(message_hash, private_key)
        r, s = signature

        assert isinstance(r, int)
        assert isinstance(s, int)
        assert 0 < r < self.dsa.q
        assert 0 < s < self.dsa.q

        # Xác thực
        is_valid = self.dsa.verify(message_hash, signature, public_key)
        assert is_valid is True

    def test_verify_invalid_signature(self):
        """Test xác thực chữ ký không hợp lệ"""
        message = "Hello, DSA!"
        message_hash = hash_message(message)

        private_key, public_key = self.dsa.generate_key_pair()

        # Ký
        signature = self.dsa.sign(message_hash, private_key)
        r, s = signature

        # Thay đổi signature
        invalid_signature = (r + 1, s)

        # Xác thực với signature sai
        is_valid = self.dsa.verify(message_hash, invalid_signature, public_key)
        assert is_valid is False

    def test_verify_tampered_message(self):
        """Test xác thực khi message bị thay đổi"""
        original_message = "Hello, DSA!"
        tampered_message = "Hello, DSA!!"

        original_hash = hash_message(original_message)
        tampered_hash = hash_message(tampered_message)

        private_key, public_key = self.dsa.generate_key_pair()

        # Ký message gốc
        signature = self.dsa.sign(original_hash, private_key)

        # Xác thực với message bị thay đổi
        is_valid = self.dsa.verify(tampered_hash, signature, public_key)
        assert is_valid is False

    def test_verify_wrong_public_key(self):
        """Test xác thực với public key sai"""
        message = "Hello, DSA!"
        message_hash = hash_message(message)

        private_key1, public_key1 = self.dsa.generate_key_pair()
        private_key2, public_key2 = self.dsa.generate_key_pair()

        # Ký với private_key1
        signature = self.dsa.sign(message_hash, private_key1)

        # Xác thực với public_key2 (sai)
        is_valid = self.dsa.verify(message_hash, signature, public_key2)
        assert is_valid is False

    def test_multiple_signatures_different(self):
        """Test nhiều chữ ký của cùng message phải khác nhau (do k ngẫu nhiên)"""
        message = "Hello, DSA!"
        message_hash = hash_message(message)

        private_key, public_key = self.dsa.generate_key_pair()

        signature1 = self.dsa.sign(message_hash, private_key)
        signature2 = self.dsa.sign(message_hash, private_key)

        # Hai chữ ký phải khác nhau (do k ngẫu nhiên)
        assert signature1 != signature2

        # Nhưng cả hai đều hợp lệ
        assert self.dsa.verify(message_hash, signature1, public_key)
        assert self.dsa.verify(message_hash, signature2, public_key)

    def test_sign_with_invalid_private_key(self):
        """Test ký với private key không hợp lệ"""
        message_hash = hash_message("Test")

        # Private key = 0 (không hợp lệ)
        with pytest.raises(ValueError):
            self.dsa.sign(message_hash, 0)

        # Private key >= q (không hợp lệ)
        with pytest.raises(ValueError):
            self.dsa.sign(message_hash, self.dsa.q)

    def test_verify_with_invalid_signature_values(self):
        """Test xác thực với giá trị signature không hợp lệ"""
        message_hash = hash_message("Test")
        private_key, public_key = self.dsa.generate_key_pair()

        # r = 0 (không hợp lệ)
        is_valid = self.dsa.verify(message_hash, (0, 123), public_key)
        assert is_valid is False

        # s = 0 (không hợp lệ)
        is_valid = self.dsa.verify(message_hash, (123, 0), public_key)
        assert is_valid is False

        # r >= q (không hợp lệ)
        is_valid = self.dsa.verify(message_hash, (self.dsa.q, 123), public_key)
        assert is_valid is False

    def test_get_params(self):
        """Test lấy thông tin tham số"""
        params = self.dsa.get_params()

        assert 'p' in params
        assert 'q' in params
        assert 'g' in params
        assert 'p_bits' in params
        assert 'q_bits' in params

        assert params['p'] == self.dsa.p
        assert params['q'] == self.dsa.q
        assert params['g'] == self.dsa.g


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
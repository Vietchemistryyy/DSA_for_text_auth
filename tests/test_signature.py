"""
Unit tests cho DSA Signature
"""
import pytest
import sys
import os
import json
import tempfile
from pathlib import Path

# Thêm src vào path
# sys.path.insert(0, str(Path(__file__).parent.parent / 'src'))

from src.signature import DSASignature
from src.key_manager import KeyManager


class TestDSASignature:
    """Test cases cho DSASignature"""

    def setup_method(self):
        """Setup trước mỗi test"""
        self.key_manager = KeyManager()
        self.key_manager.generate_keys(verbose=False)
        self.signature = DSASignature(self.key_manager)

    def test_init(self):
        """Test khởi tạo"""
        assert self.signature.key_manager is not None
        assert self.signature.dsa is not None

    def test_sign_message_success(self):
        """Test ký message thành công"""
        message = "Hello, World!"
        signature = self.signature.sign_message(message)

        r, s = signature
        assert isinstance(r, int)
        assert isinstance(s, int)
        assert 0 < r < self.signature.dsa.q
        assert 0 < s < self.signature.dsa.q

    def test_sign_message_without_private_key(self):
        """Test ký message khi chưa có private key"""
        signature_no_key = DSASignature()

        with pytest.raises(ValueError, match="Chưa có private key"):
            signature_no_key.sign_message("Test")

    def test_verify_message_valid(self):
        """Test xác thực message hợp lệ"""
        message = "Hello, World!"
        signature = self.signature.sign_message(message)

        is_valid = self.signature.verify_message(message, signature)
        assert is_valid is True

    def test_verify_message_tampered(self):
        """Test xác thực message bị thay đổi"""
        original_message = "Hello, World!"
        tampered_message = "Hello, World!!"

        signature = self.signature.sign_message(original_message)

        is_valid = self.signature.verify_message(tampered_message, signature)
        assert is_valid is False

    def test_verify_message_invalid_signature(self):
        """Test xác thực với chữ ký sai"""
        message = "Hello, World!"
        signature = self.signature.sign_message(message)

        r, s = signature
        invalid_signature = (r + 1, s)

        is_valid = self.signature.verify_message(message, invalid_signature)
        assert is_valid is False

    def test_verify_message_with_external_public_key(self):
        """Test xác thực với public key từ bên ngoài"""
        message = "Hello, World!"
        signature = self.signature.sign_message(message)
        public_key = self.key_manager.get_public_key()

        # Tạo signature mới không có key
        new_signature = DSASignature()

        is_valid = new_signature.verify_message(message, signature, public_key)
        assert is_valid is True

    def test_sign_and_verify_file(self):
        """Test ký và xác thực file"""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Tạo file văn bản
            input_file = Path(tmpdir) / "test.txt"
            input_file.write_text("This is a test file.", encoding='utf-8')

            sig_file = Path(tmpdir) / "test.txt.sig"

            # Ký file
            signature = self.signature.sign_file(str(input_file), str(sig_file))
            assert sig_file.exists()

            # Kiểm tra nội dung file chữ ký
            with open(sig_file, 'r') as f:
                sig_data = json.load(f)

            assert 'signature' in sig_data
            assert 'r' in sig_data['signature']
            assert 's' in sig_data['signature']

            # Xác thực file
            is_valid = self.signature.verify_file(str(input_file), str(sig_file))
            assert is_valid is True

    def test_verify_file_tampered(self):
        """Test xác thực file bị thay đổi"""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Tạo file văn bản
            input_file = Path(tmpdir) / "test.txt"
            input_file.write_text("Original content", encoding='utf-8')

            sig_file = Path(tmpdir) / "test.txt.sig"

            # Ký file
            self.signature.sign_file(str(input_file), str(sig_file))

            # Thay đổi nội dung file
            input_file.write_text("Modified content", encoding='utf-8')

            # Xác thực file bị thay đổi
            is_valid = self.signature.verify_file(str(input_file), str(sig_file))
            assert is_valid is False

    def test_create_signature_package(self):
        """Test tạo gói chữ ký hoàn chỉnh"""
        with tempfile.TemporaryDirectory() as tmpdir:
            message = "Test package"
            package_file = Path(tmpdir) / "package.json"

            self.signature.create_signature_package(message, str(package_file))

            assert package_file.exists()

            # Kiểm tra nội dung package
            with open(package_file, 'r') as f:
                package = json.load(f)

            assert 'message' in package
            assert 'signature' in package
            assert 'public_key' in package
            assert 'algorithm' in package
            assert 'params' in package

            assert package['message'] == message

    def test_verify_signature_package(self):
        """Test xác thực gói chữ ký"""
        with tempfile.TemporaryDirectory() as tmpdir:
            message = "Test package verification"
            package_file = Path(tmpdir) / "package.json"

            # Tạo package
            self.signature.create_signature_package(message, str(package_file))

            # Tạo signature mới để xác thực
            new_signature = DSASignature()

            # Xác thực package
            is_valid = new_signature.verify_signature_package(str(package_file))
            assert is_valid is True

    def test_verify_tampered_package(self):
        """Test xác thực gói chữ ký bị thay đổi"""
        with tempfile.TemporaryDirectory() as tmpdir:
            message = "Original message"
            package_file = Path(tmpdir) / "package.json"

            # Tạo package
            self.signature.create_signature_package(message, str(package_file))

            # Thay đổi message trong package
            with open(package_file, 'r') as f:
                package = json.load(f)

            package['message'] = "Tampered message"

            with open(package_file, 'w') as f:
                json.dump(package, f)

            # Xác thực package bị thay đổi
            new_signature = DSASignature()
            is_valid = new_signature.verify_signature_package(str(package_file))
            assert is_valid is False

    def test_batch_sign_files(self):
        """Test ký hàng loạt file"""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Tạo nhiều file
            files = []
            for i in range(3):
                file_path = Path(tmpdir) / f"file{i}.txt"
                file_path.write_text(f"Content {i}", encoding='utf-8')
                files.append(str(file_path))

            output_dir = Path(tmpdir) / "signatures"

            # Ký hàng loạt
            self.signature.batch_sign_files(files, str(output_dir))

            # Kiểm tra tất cả file chữ ký đã được tạo
            for file_path in files:
                filename = Path(file_path).name
                sig_file = output_dir / f"{filename}.sig"
                assert sig_file.exists()

    def test_different_hash_algorithms(self):
        """Test với các thuật toán hash khác nhau"""
        message = "Test hash algorithms"

        for algorithm in ['sha256', 'sha1', 'md5']:
            signature = self.signature.sign_message(message, algorithm)
            is_valid = self.signature.verify_message(message, signature,
                                                     hash_algorithm=algorithm)
            assert is_valid is True


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
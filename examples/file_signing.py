"""
Ví dụ nâng cao: Hệ thống ký và xác thực file
"""
import sys
import argparse
from pathlib import Path

# Thêm src vào path
# sys.path.insert(0, str(Path(__file__).parent.parent / 'src'))

from src.key_manager import KeyManager
from src.signature import DSASignature


class FileSigningSystem:
    """Hệ thống ký và xác thực file"""

    def __init__(self, keys_dir: str = "signing_keys"):
        """
        Khởi tạo hệ thống

        Args:
            keys_dir: Thư mục lưu khóa
        """
        self.keys_dir = Path(keys_dir)
        self.keys_dir.mkdir(exist_ok=True)

        self.private_key_file = self.keys_dir / "private_key.json"
        self.public_key_file = self.keys_dir / "public_key.json"

        self.key_manager = KeyManager()
        self.signature = DSASignature(self.key_manager)

    def init_keys(self, force: bool = False):
        """
        Khởi tạo cặp khóa mới

        Args:
            force: Ghi đè nếu khóa đã tồn tại
        """
        if not force and self.private_key_file.exists():
            print(f"⚠️  Khóa đã tồn tại tại {self.keys_dir}")
            response = input("Bạn có muốn tạo khóa mới? (y/n): ")
            if response.lower() != 'y':
                print("Hủy tạo khóa mới.")
                return

        print(f"\n🔐 Tạo cặp khóa DSA mới...")
        self.key_manager.generate_keys()

        print(f"\n💾 Lưu khóa vào {self.keys_dir}...")
        self.key_manager.save_private_key(str(self.private_key_file))
        self.key_manager.save_public_key(str(self.public_key_file))

        print(f"\n✅ Đã khởi tạo hệ thống thành công!")
        print(f"   Private Key: {self.private_key_file}")
        print(f"   Public Key: {self.public_key_file}")

    def load_keys(self, private: bool = True, public: bool = True):
        """
        Tải khóa từ file

        Args:
            private: Tải private key
            public: Tải public key
        """
        if private and self.private_key_file.exists():
            self.key_manager.load_private_key(str(self.private_key_file))

        if public and self.public_key_file.exists():
            self.key_manager.load_public_key(str(self.public_key_file))

    def sign_file(self, filepath: str, output: str = None):
        """
        Ký file

        Args:
            filepath: Đường dẫn file cần ký
            output: Đường dẫn file chữ ký (mặc định: filepath + .sig)
        """
        file_path = Path(filepath)

        if not file_path.exists():
            print(f"❌ Lỗi: File không tồn tại: {filepath}")
            return

        # Tải private key nếu chưa có
        if not self.key_manager.has_private_key():
            if not self.private_key_file.exists():
                print(f"❌ Lỗi: Chưa có private key. Hãy chạy 'init' trước.")
                return
            self.load_keys(private=True, public=False)

        # Ký file
        print(f"\n✍️  Đang ký file: {file_path.name}")
        if output is None:
            output = str(file_path) + ".sig"

        self.signature.sign_file(str(file_path), output)

        print(f"\n✅ Đã ký file thành công!")
        print(f"   Chữ ký: {output}")

    def verify_file(self, filepath: str, signature_file: str = None,
                    public_key_file: str = None):
        """
        Xác thực file

        Args:
            filepath: Đường dẫn file cần xác thực
            signature_file: Đường dẫn file chữ ký (mặc định: filepath + .sig)
            public_key_file: Đường dẫn public key (mặc định: dùng key hệ thống)
        """
        file_path = Path(filepath)

        if not file_path.exists():
            print(f"❌ Lỗi: File không tồn tại: {filepath}")
            return

        if signature_file is None:
            signature_file = str(file_path) + ".sig"

        sig_path = Path(signature_file)
        if not sig_path.exists():
            print(f"❌ Lỗi: File chữ ký không tồn tại: {signature_file}")
            return

        # Tải public key
        if public_key_file:
            temp_km = KeyManager()
            temp_km.load_public_key(public_key_file)
            public_key = temp_km.get_public_key()
        else:
            if not self.key_manager.has_public_key():
                if not self.public_key_file.exists():
                    print(f"❌ Lỗi: Chưa có public key.")
                    return
                self.load_keys(private=False, public=True)
            public_key = None

        # Xác thực
        print(f"\n🔍 Đang xác thực file: {file_path.name}")
        is_valid = self.signature.verify_file(str(file_path), signature_file, public_key)

        if is_valid:
            print(f"\n✅ KẾT QUẢ: File hợp lệ và chưa bị thay đổi!")
        else:
            print(f"\n❌ KẾT QUẢ: File không hợp lệ hoặc đã bị thay đổi!")

    def batch_sign(self, directory: str, pattern: str = "*.txt"):
        """
        Ký hàng loạt file trong thư mục

        Args:
            directory: Thư mục chứa file
            pattern: Pattern để lọc file
        """
        dir_path = Path(directory)

        if not dir_path.exists():
            print(f"❌ Lỗi: Thư mục không tồn tại: {directory}")
            return

        # Tìm tất cả file matching pattern
        files = list(dir_path.glob(pattern))

        if not files:
            print(f"⚠️  Không tìm thấy file nào với pattern '{pattern}' trong {directory}")
            return

        print(f"\n📁 Tìm thấy {len(files)} file để ký:")
        for f in files:
            print(f"   - {f.name}")

        response = input(f"\nTiếp tục ký {len(files)} file? (y/n): ")
        if response.lower() != 'y':
            print("Đã hủy.")
            return

        # Tải private key nếu chưa có
        if not self.key_manager.has_private_key():
            if not self.private_key_file.exists():
                print(f"❌ Lỗi: Chưa có private key. Hãy chạy 'init' trước.")
                return
            self.load_keys(private=True, public=False)

        # Ký hàng loạt
        sig_dir = dir_path / "signatures"
        self.signature.batch_sign_files([str(f) for f in files], str(sig_dir))

    def export_public_key(self, output: str):
        """
        Export public key để chia sẻ

        Args:
            output: Đường dẫn file output
        """
        if not self.key_manager.has_public_key():
            if not self.public_key_file.exists():
                print(f"❌ Lỗi: Chưa có public key.")
                return
            self.load_keys(private=False, public=True)

        output_path = Path(output)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        self.key_manager.save_public_key(str(output_path))
        print(f"\n✅ Đã export public key: {output}")
        print(f"   Bạn có thể chia sẻ file này để người khác xác thực chữ ký của bạn.")


def main():
    """CLI cho hệ thống ký file"""
    parser = argparse.ArgumentParser(
        description="Hệ thống ký và xác thực file DSA",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ví dụ sử dụng:
  %(prog)s init                          # Khởi tạo khóa mới
  %(prog)s sign document.txt             # Ký file
  %(prog)s verify document.txt           # Xác thực file
  %(prog)s batch-sign ./documents        # Ký hàng loạt
  %(prog)s export-key my_public_key.json # Export public key
        """
    )

    parser.add_argument(
        'command',
        choices=['init', 'sign', 'verify', 'batch-sign', 'export-key'],
        help='Lệnh cần thực hiện'
    )

    parser.add_argument(
        'target',
        nargs='?',
        help='File hoặc thư mục mục tiêu'
    )

    parser.add_argument(
        '--keys-dir',
        default='signing_keys',
        help='Thư mục chứa khóa (mặc định: signing_keys)'
    )

    parser.add_argument(
        '--signature',
        help='Đường dẫn file chữ ký (cho lệnh verify)'
    )

    parser.add_argument(
        '--public-key',
        help='Đường dẫn public key (cho lệnh verify)'
    )

    parser.add_argument(
        '--pattern',
        default='*.txt',
        help='Pattern file cho batch-sign (mặc định: *.txt)'
    )

    parser.add_argument(
        '--output',
        help='Đường dẫn file output'
    )

    parser.add_argument(
        '--force',
        action='store_true',
        help='Ghi đè nếu file đã tồn tại'
    )

    args = parser.parse_args()

    # Khởi tạo hệ thống
    system = FileSigningSystem(args.keys_dir)

    # Thực thi lệnh
    if args.command == 'init':
        system.init_keys(force=args.force)

    elif args.command == 'sign':
        if not args.target:
            print("❌ Lỗi: Cần chỉ định file để ký")
            parser.print_help()
            return
        system.sign_file(args.target, args.output)

    elif args.command == 'verify':
        if not args.target:
            print("❌ Lỗi: Cần chỉ định file để xác thực")
            parser.print_help()
            return
        system.verify_file(args.target, args.signature, args.public_key)

    elif args.command == 'batch-sign':
        if not args.target:
            print("❌ Lỗi: Cần chỉ định thư mục")
            parser.print_help()
            return
        system.batch_sign(args.target, args.pattern)

    elif args.command == 'export-key':
        if not args.target:
            print("❌ Lỗi: Cần chỉ định file output")
            parser.print_help()
            return
        system.export_public_key(args.target)


if __name__ == "__main__":
    main()
"""
DSA Digital Signature System - Main Entry Point
Chương trình chính để chạy hệ thống chữ ký số DSA
"""
import sys
from pathlib import Path

# Thêm src vào path
sys.path.insert(0, str(Path(__file__).parent / 'src'))

from src import KeyManager, DSASignature
from src.utils import print_key_info


def print_banner():
    """In banner chào mừng"""
    banner = """
    ╔═══════════════════════════════════════════════════════════╗
    ║                                                           ║
    ║           🔐 DSA DIGITAL SIGNATURE SYSTEM 🔐              ║
    ║                                                           ║
    ║         Hệ thống Chữ ký Số DSA - An toàn & Tin cậy       ║
    ║                                                           ║
    ╚═══════════════════════════════════════════════════════════╝
    """
    print(banner)


def print_menu():
    """In menu chính"""
    menu = """
    ┌─────────────────────────────────────────────────────────┐
    │                      MENU CHÍNH                         │
    ├─────────────────────────────────────────────────────────┤
    │  1. Quản lý Khóa                                        │
    │  2. Ký Văn bản                                          │
    │  3. Xác thực Chữ ký                                     │
    │  4. Ký File                                             │
    │  5. Xác thực File                                       │
    │  6. Tạo Gói Chữ ký Hoàn chỉnh                           │
    │  7. Xác thực Gói Chữ ký                                 │
    │  8. Demo Nhanh                                          │
    │  0. Thoát                                               │
    └─────────────────────────────────────────────────────────┘
    """
    print(menu)


def menu_key_management(key_manager):
    """Menu quản lý khóa"""
    while True:
        print("\n" + "=" * 60)
        print("           QUẢN LÝ KHÓA")
        print("=" * 60)
        print("1. Tạo cặp khóa mới")
        print("2. Lưu Private Key")
        print("3. Lưu Public Key")
        print("4. Tải Private Key")
        print("5. Tải Public Key")
        print("6. Xem thông tin khóa hiện tại")
        print("7. Xóa khóa trong bộ nhớ")
        print("0. Quay lại")

        choice = input("\nChọn chức năng: ").strip()

        if choice == '1':
            print("\n🔑 Đang tạo cặp khóa mới...")
            key_manager.generate_keys()

        elif choice == '2':
            if not key_manager.has_private_key():
                print("❌ Chưa có private key!")
                continue
            filepath = input("Nhập đường dẫn lưu (mặc định: keys/private_key.json): ").strip()
            if not filepath:
                filepath = "keys/private_key.json"
            key_manager.save_private_key(filepath)

        elif choice == '3':
            if not key_manager.has_public_key():
                print("❌ Chưa có public key!")
                continue
            filepath = input("Nhập đường dẫn lưu (mặc định: keys/public_key.json): ").strip()
            if not filepath:
                filepath = "keys/public_key.json"
            key_manager.save_public_key(filepath)

        elif choice == '4':
            filepath = input("Nhập đường dẫn file private key: ").strip()
            if filepath:
                try:
                    key_manager.load_private_key(filepath)
                except Exception as e:
                    print(f"❌ Lỗi: {e}")

        elif choice == '5':
            filepath = input("Nhập đường dẫn file public key: ").strip()
            if filepath:
                try:
                    key_manager.load_public_key(filepath)
                except Exception as e:
                    print(f"❌ Lỗi: {e}")

        elif choice == '6':
            print("\n" + "=" * 60)
            print("THÔNG TIN KHÓA HIỆN TẠI")
            print("=" * 60)
            if key_manager.has_private_key():
                print_key_info("Private", key_manager.get_private_key())
            else:
                print("❌ Chưa có Private Key")

            if key_manager.has_public_key():
                print_key_info("Public", key_manager.get_public_key())
            else:
                print("❌ Chưa có Public Key")

        elif choice == '7':
            confirm = input("⚠️  Xác nhận xóa tất cả khóa? (y/n): ").strip().lower()
            if confirm == 'y':
                key_manager.clear_keys()

        elif choice == '0':
            break

        else:
            print("❌ Lựa chọn không hợp lệ!")


def menu_sign_message(signature):
    """Menu ký văn bản"""
    print("\n" + "=" * 60)
    print("           KÝ VĂN BẢN")
    print("=" * 60)

    if not signature.key_manager.has_private_key():
        print("❌ Chưa có private key! Hãy tạo hoặc tải khóa trước.")
        return

    print("\nNhập văn bản cần ký (Enter 2 lần để kết thúc):")
    lines = []
    while True:
        line = input()
        if line == "" and len(lines) > 0 and lines[-1] == "":
            lines.pop()
            break
        lines.append(line)

    message = "\n".join(lines)

    if not message.strip():
        print("❌ Văn bản trống!")
        return

    try:
        sig = signature.sign_message(message)
        print(f"\n💾 Lưu chữ ký?")
        save = input("Nhập đường dẫn file (Enter để bỏ qua): ").strip()

        if save:
            import json
            from src.utils import format_hex

            sig_data = {
                'message': message,
                'signature': {
                    'r': format_hex(sig[0], prefix=False),
                    's': format_hex(sig[1], prefix=False)
                }
            }

            Path(save).parent.mkdir(parents=True, exist_ok=True)
            with open(save, 'w', encoding='utf-8') as f:
                json.dump(sig_data, f, indent=2, ensure_ascii=False)
            print(f"✅ Đã lưu chữ ký: {save}")

    except Exception as e:
        print(f"❌ Lỗi: {e}")


def menu_verify_message(signature):
    """Menu xác thực văn bản"""
    print("\n" + "=" * 60)
    print("           XÁC THỰC CHỮ KÝ")
    print("=" * 60)

    print("\n1. Nhập thủ công")
    print("2. Tải từ file")
    choice = input("Chọn: ").strip()

    if choice == '1':
        print("\nNhập văn bản gốc (Enter 2 lần để kết thúc):")
        lines = []
        while True:
            line = input()
            if line == "" and len(lines) > 0 and lines[-1] == "":
                lines.pop()
                break
            lines.append(line)

        message = "\n".join(lines)

        r = input("\nNhập r (hex): ").strip()
        s = input("Nhập s (hex): ").strip()

        try:
            r_int = int(r, 16) if r.startswith('0x') else int(r, 16)
            s_int = int(s, 16) if s.startswith('0x') else int(s, 16)
            sig = (r_int, s_int)

            # Public key
            if not signature.key_manager.has_public_key():
                pub_key_hex = input("\nNhập public key (hex): ").strip()
                pub_key = int(pub_key_hex, 16) if pub_key_hex.startswith('0x') else int(pub_key_hex, 16)
            else:
                pub_key = None

            signature.verify_message(message, sig, pub_key)

        except Exception as e:
            print(f"❌ Lỗi: {e}")

    elif choice == '2':
        filepath = input("Nhập đường dẫn file chữ ký: ").strip()
        try:
            import json
            with open(filepath, 'r', encoding='utf-8') as f:
                data = json.load(f)

            message = data['message']
            r = int(data['signature']['r'], 16)
            s = int(data['signature']['s'], 16)
            sig = (r, s)

            if 'public_key' in data:
                pub_key = int(data['public_key'], 16)
            else:
                pub_key = None

            signature.verify_message(message, sig, pub_key)

        except Exception as e:
            print(f"❌ Lỗi: {e}")


def menu_sign_file(signature):
    """Menu ký file"""
    print("\n" + "=" * 60)
    print("           KÝ FILE")
    print("=" * 60)

    if not signature.key_manager.has_private_key():
        print("❌ Chưa có private key! Hãy tạo hoặc tải khóa trước.")
        return

    filepath = input("\nNhập đường dẫn file cần ký: ").strip()

    if not Path(filepath).exists():
        print(f"❌ File không tồn tại: {filepath}")
        return

    output = input("Đường dẫn lưu chữ ký (Enter để dùng mặc định): ").strip()
    if not output:
        output = filepath + ".sig"

    try:
        signature.sign_file(filepath, output)
    except Exception as e:
        print(f"❌ Lỗi: {e}")


def menu_verify_file(signature):
    """Menu xác thực file"""
    print("\n" + "=" * 60)
    print("           XÁC THỰC FILE")
    print("=" * 60)

    filepath = input("\nNhập đường dẫn file cần xác thực: ").strip()

    if not Path(filepath).exists():
        print(f"❌ File không tồn tại: {filepath}")
        return

    sig_file = input("Đường dẫn file chữ ký (Enter để dùng mặc định): ").strip()
    if not sig_file:
        sig_file = filepath + ".sig"

    if not Path(sig_file).exists():
        print(f"❌ File chữ ký không tồn tại: {sig_file}")
        return

    try:
        signature.verify_file(filepath, sig_file)
    except Exception as e:
        print(f"❌ Lỗi: {e}")


def quick_demo():
    """Demo nhanh toàn bộ quy trình"""
    print("\n" + "=" * 60)
    print("           DEMO NHANH")
    print("=" * 60)

    print("\n🚀 Bắt đầu demo...")

    # Tạo khóa
    print("\n📍 Bước 1: Tạo cặp khóa")
    km = KeyManager()
    km.generate_keys(verbose=False)
    print("✅ Đã tạo cặp khóa")

    # Ký message
    print("\n📍 Bước 2: Ký văn bản")
    sig = DSASignature(km)
    message = "Đây là một văn bản demo cho hệ thống chữ ký số DSA!"
    print(f"📝 Message: {message}")

    signature = sig.sign_message(message)
    print("✅ Đã ký văn bản")

    # Xác thực
    print("\n📍 Bước 3: Xác thực chữ ký")
    is_valid = sig.verify_message(message, signature)

    # Thử với message sai
    print("\n📍 Bước 4: Thử xác thực với văn bản bị thay đổi")
    tampered = message + " (đã sửa đổi)"
    is_valid_tampered = sig.verify_message(tampered, signature)

    print("\n" + "=" * 60)
    print("✅ DEMO HOÀN TẤT!")
    print("=" * 60)

    input("\nNhấn Enter để tiếp tục...")


def main():
    """Hàm chính"""
    print_banner()

    # Khởi tạo
    key_manager = KeyManager()
    signature = DSASignature(key_manager)

    while True:
        print_menu()
        choice = input("Chọn chức năng: ").strip()

        if choice == '1':
            menu_key_management(key_manager)

        elif choice == '2':
            menu_sign_message(signature)

        elif choice == '3':
            menu_verify_message(signature)

        elif choice == '4':
            menu_sign_file(signature)

        elif choice == '5':
            menu_verify_file(signature)

        elif choice == '6':
            if not signature.key_manager.has_private_key():
                print("❌ Chưa có private key!")
                continue

            message = input("\nNhập văn bản: ").strip()
            output = input("Đường dẫn lưu gói: ").strip()

            if message and output:
                try:
                    signature.create_signature_package(message, output)
                except Exception as e:
                    print(f"❌ Lỗi: {e}")

        elif choice == '7':
            filepath = input("\nNhập đường dẫn gói chữ ký: ").strip()
            if filepath:
                try:
                    new_sig = DSASignature()
                    new_sig.verify_signature_package(filepath)
                except Exception as e:
                    print(f"❌ Lỗi: {e}")

        elif choice == '8':
            quick_demo()

        elif choice == '0':
            print("\n👋 Cảm ơn bạn đã sử dụng DSA Digital Signature System!")
            print("Hẹn gặp lại! 🔐\n")
            break

        else:
            print("❌ Lựa chọn không hợp lệ!")

        input("\nNhấn Enter để tiếp tục...")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n👋 Đã hủy chương trình. Tạm biệt!")
    except Exception as e:
        print(f"\n❌ Lỗi nghiêm trọng: {e}")
        import traceback

        traceback.print_exc()
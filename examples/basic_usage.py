"""
Ví dụ sử dụng cơ bản của DSA Signature
"""
import sys
from pathlib import Path

# Thêm src vào path
# sys.path.insert(0, str(Path(__file__).parent.parent / 'src'))

from src.key_manager import KeyManager
from src.signature import DSASignature


def example_basic_sign_verify():
    """Ví dụ cơ bản: Ký và xác thực message"""
    print("\n" + "=" * 70)
    print("VÍ DỤ 1: KÝ VÀ XÁC THỰC MESSAGE CƠ BẢN")
    print("=" * 70)

    # Bước 1: Tạo Key Manager và sinh khóa
    key_manager = KeyManager()
    key_manager.generate_keys()

    # Bước 2: Tạo DSA Signature
    dsa_sig = DSASignature(key_manager)

    # Bước 3: Ký message
    message = "Xin chào! Đây là văn bản cần được xác thực."
    print(f"\n📝 Message gốc: {message}")

    signature = dsa_sig.sign_message(message)

    # Bước 4: Xác thực chữ ký
    print(f"\n🔍 Đang xác thực chữ ký...")
    is_valid = dsa_sig.verify_message(message, signature)

    # Bước 5: Thử xác thực với message bị thay đổi
    print(f"\n🔍 Thử xác thực với message bị thay đổi...")
    tampered_message = message + " (đã bị sửa đổi)"
    is_valid_tampered = dsa_sig.verify_message(tampered_message, signature)


def example_save_load_keys():
    """Ví dụ: Lưu và tải khóa"""
    print("\n" + "=" * 70)
    print("VÍ DỤ 2: LƯU VÀ TẢI KHÓA")
    print("=" * 70)

    # Tạo thư mục keys nếu chưa có
    keys_dir = Path("keys")
    keys_dir.mkdir(exist_ok=True)

    # Bước 1: Tạo và lưu khóa
    print("\n📁 Tạo và lưu khóa...")
    key_manager = KeyManager()
    key_manager.generate_keys()

    private_key_file = keys_dir / "private_key.json"
    public_key_file = keys_dir / "public_key.json"

    key_manager.save_private_key(str(private_key_file))
    key_manager.save_public_key(str(public_key_file))

    # Bước 2: Tải khóa từ file
    print(f"\n📂 Tải khóa từ file...")
    new_key_manager = KeyManager()
    new_key_manager.load_private_key(str(private_key_file))
    new_key_manager.load_public_key(str(public_key_file))

    # Bước 3: Sử dụng khóa đã tải để ký
    dsa_sig = DSASignature(new_key_manager)
    message = "Message với khóa đã được lưu và tải lại"

    signature = dsa_sig.sign_message(message)
    is_valid = dsa_sig.verify_message(message, signature)

    print(f"\n✅ Đã sử dụng khóa từ file thành công!")


def example_cross_verification():
    """Ví dụ: Xác thực chéo giữa 2 người dùng"""
    print("\n" + "=" * 70)
    print("VÍ DỤ 3: XÁC THỰC CHÉO (ALICE GỬI MESSAGE CHO BOB)")
    print("=" * 70)

    # Alice tạo khóa và ký message
    print("\n👤 Alice tạo khóa và ký message...")
    alice_km = KeyManager()
    alice_km.generate_keys(verbose=False)
    alice_sig = DSASignature(alice_km)

    message = "Gửi Bob: Đây là tin nhắn quan trọng từ Alice."
    signature = alice_sig.sign_message(message)
    alice_public_key = alice_km.get_public_key()

    print(f"📝 Message: {message}")
    print(f"🔑 Alice chia sẻ public key với Bob")

    # Bob nhận message, signature và public key từ Alice
    print(f"\n👤 Bob nhận message và xác thực...")
    bob_sig = DSASignature()

    is_valid = bob_sig.verify_message(message, signature, alice_public_key)

    if is_valid:
        print(f"✅ Bob xác nhận: Message từ Alice là hợp lệ!")
    else:
        print(f"❌ Bob cảnh báo: Message không hợp lệ!")


def example_sign_verify_file():
    """Ví dụ: Ký và xác thực file"""
    print("\n" + "=" * 70)
    print("VÍ DỤ 4: KÝ VÀ XÁC THỰC FILE")
    print("=" * 70)

    # Tạo thư mục documents nếu chưa có
    docs_dir = Path("documents")
    docs_dir.mkdir(exist_ok=True)

    # Bước 1: Tạo file văn bản mẫu
    test_file = docs_dir / "contract.txt"
    contract_content = """
HDỢP ĐỒNG MUA BÁN
==================
Bên A: Công ty ABC
Bên B: Công ty XYZ

Điều khoản:
1. Bên A bán cho Bên B...
2. Giá trị hợp đồng...
3. Thời hạn thực hiện...
    """

    test_file.write_text(contract_content, encoding='utf-8')
    print(f"\n📄 Đã tạo file hợp đồng: {test_file}")

    # Bước 2: Ký file
    key_manager = KeyManager()
    key_manager.generate_keys(verbose=False)
    dsa_sig = DSASignature(key_manager)

    print(f"\n✍️  Đang ký file...")
    sig_file = docs_dir / "contract.txt.sig"
    dsa_sig.sign_file(str(test_file), str(sig_file))

    # Bước 3: Xác thực file
    print(f"\n🔍 Xác thực file...")
    is_valid = dsa_sig.verify_file(str(test_file), str(sig_file))

    # Bước 4: Thử thay đổi file và xác thực lại
    print(f"\n⚠️  Thử thay đổi nội dung file...")
    test_file.write_text(contract_content + "\n(Đã sửa đổi)", encoding='utf-8')

    print(f"🔍 Xác thực lại file sau khi sửa đổi...")
    is_valid_tampered = dsa_sig.verify_file(str(test_file), str(sig_file))


def example_signature_package():
    """Ví dụ: Tạo và xác thực gói chữ ký hoàn chỉnh"""
    print("\n" + "=" * 70)
    print("VÍ DỤ 5: GÓI CHỮ KÝ HOÀN CHỈNH (MESSAGE + SIGNATURE + PUBLIC KEY)")
    print("=" * 70)

    packages_dir = Path("packages")
    packages_dir.mkdir(exist_ok=True)

    # Bước 1: Tạo gói chữ ký
    key_manager = KeyManager()
    key_manager.generate_keys(verbose=False)
    dsa_sig = DSASignature(key_manager)

    message = "Thông báo: Họp tổng kết vào ngày 15/12/2024 lúc 9:00 AM"
    package_file = packages_dir / "announcement.json"

    print(f"\n📦 Tạo gói chữ ký hoàn chỉnh...")
    dsa_sig.create_signature_package(message, str(package_file))

    # Bước 2: Người khác xác thực gói (không cần biết trước public key)
    print(f"\n🔍 Người nhận xác thực gói chữ ký...")
    receiver_sig = DSASignature()
    is_valid = receiver_sig.verify_signature_package(str(package_file))

    if is_valid:
        print(f"✅ Gói chữ ký hợp lệ! Message an toàn để sử dụng.")
    else:
        print(f"❌ Cảnh báo: Gói chữ ký không hợp lệ!")


def example_batch_signing():
    """Ví dụ: Ký hàng loạt file"""
    print("\n" + "=" * 70)
    print("VÍ DỤ 6: KÝ HÀNG LOẠT FILE")
    print("=" * 70)

    # Tạo thư mục batch
    batch_dir = Path("batch_files")
    batch_dir.mkdir(exist_ok=True)

    # Tạo nhiều file
    print(f"\n📁 Tạo nhiều file văn bản...")
    files = []
    for i in range(5):
        file_path = batch_dir / f"document_{i + 1}.txt"
        file_path.write_text(f"Nội dung văn bản số {i + 1}", encoding='utf-8')
        files.append(str(file_path))
        print(f"   ✓ {file_path.name}")

    # Ký hàng loạt
    key_manager = KeyManager()
    key_manager.generate_keys(verbose=False)
    dsa_sig = DSASignature(key_manager)

    print(f"\n✍️  Ký hàng loạt {len(files)} file...")
    signatures_dir = batch_dir / "signatures"
    dsa_sig.batch_sign_files(files, str(signatures_dir))


def main():
    """Chạy tất cả các ví dụ"""
    print("\n" + "=" * 70)
    print("🔐 DSA DIGITAL SIGNATURE - CÁC VÍ DỤ SỬ DỤNG")
    print("=" * 70)

    examples = [
        ("Ví dụ cơ bản", example_basic_sign_verify),
        ("Lưu và tải khóa", example_save_load_keys),
        ("Xác thực chéo", example_cross_verification),
        ("Ký và xác thực file", example_sign_verify_file),
        ("Gói chữ ký hoàn chỉnh", example_signature_package),
        ("Ký hàng loạt", example_batch_signing)
    ]

    print("\nChọn ví dụ để chạy:")
    for i, (name, _) in enumerate(examples, 1):
        print(f"{i}. {name}")
    print(f"{len(examples) + 1}. Chạy tất cả")
    print("0. Thoát")

    try:
        choice = int(input("\nNhập lựa chọn: "))

        if choice == 0:
            print("Tạm biệt!")
            return
        elif choice == len(examples) + 1:
            for name, func in examples:
                func()
                input("\nNhấn Enter để tiếp tục...")
        elif 1 <= choice <= len(examples):
            examples[choice - 1][1]()
        else:
            print("Lựa chọn không hợp lệ!")
    except ValueError:
        print("Vui lòng nhập số!")
    except KeyboardInterrupt:
        print("\n\nĐã hủy!")


if __name__ == "__main__":
    main()
"""
Các hàm tiện ích cho DSA
"""
import hashlib
import secrets


def hash_message(message: str, algorithm: str = 'sha256') -> int:
    """
    Hash văn bản và chuyển thành số nguyên

    Args:
        message: Văn bản cần hash
        algorithm: Thuật toán hash (mặc định sha256)

    Returns:
        int: Giá trị hash dạng số nguyên
    """
    if isinstance(message, str):
        message = message.encode('utf-8')

    hasher = hashlib.new(algorithm)
    hasher.update(message)
    hash_bytes = hasher.digest()

    return bytes_to_int(hash_bytes)


def bytes_to_int(data: bytes) -> int:
    """
    Chuyển bytes thành số nguyên

    Args:
        data: Dữ liệu dạng bytes

    Returns:
        int: Số nguyên
    """
    return int.from_bytes(data, byteorder='big')


def int_to_bytes(num: int, length: int = None) -> bytes:
    """
    Chuyển số nguyên thành bytes

    Args:
        num: Số nguyên cần chuyển
        length: Độ dài bytes (tự động nếu None)

    Returns:
        bytes: Dữ liệu dạng bytes
    """
    if length is None:
        length = (num.bit_length() + 7) // 8
    return num.to_bytes(length, byteorder='big')


def generate_random_k(q: int) -> int:
    """
    Tạo số ngẫu nhiên k trong khoảng (1, q-1)

    Args:
        q: Số nguyên tố q trong DSA

    Returns:
        int: Số ngẫu nhiên k
    """
    while True:
        k = secrets.randbelow(q - 1) + 1
        if 1 < k < q:
            return k


def mod_inverse(a: int, m: int) -> int:
    """
    Tính nghịch đảo modulo sử dụng Extended Euclidean Algorithm

    Args:
        a: Số cần tìm nghịch đảo
        m: Modulo

    Returns:
        int: Nghịch đảo của a mod m

    Raises:
        ValueError: Nếu không tồn tại nghịch đảo
    """
    if m == 1:
        return 0

    m0, x0, x1 = m, 0, 1

    while a > 1:
        if m == 0:
            raise ValueError(f"Không tồn tại nghịch đảo của {a} mod {m0}")

        q = a // m
        a, m = m, a % m
        x0, x1 = x1 - q * x0, x0

    if x1 < 0:
        x1 += m0

    return x1


def validate_dsa_params(p: int, q: int, g: int) -> bool:
    """
    Kiểm tra tính hợp lệ của tham số DSA

    Args:
        p: Số nguyên tố lớn
        q: Số nguyên tố nhỏ (ước của p-1)
        g: Generator

    Returns:
        bool: True nếu hợp lệ
    """
    # Kiểm tra q là ước của p-1
    if (p - 1) % q != 0:
        return False

    # Kiểm tra g^q mod p = 1
    if pow(g, q, p) != 1:
        return False

    # Kiểm tra 1 < g < p
    if not (1 < g < p):
        return False

    return True


def format_hex(num: int, prefix: bool = True) -> str:
    """
    Format số nguyên thành chuỗi hex

    Args:
        num: Số nguyên
        prefix: Có thêm '0x' hay không

    Returns:
        str: Chuỗi hex
    """
    hex_str = hex(num)[2:]
    return f"0x{hex_str}" if prefix else hex_str


def print_key_info(key_type: str, key_value: int, bit_length: int = None):
    """
    In thông tin khóa ra console

    Args:
        key_type: Loại khóa (Private/Public)
        key_value: Giá trị khóa
        bit_length: Độ dài bit (tự động tính nếu None)
    """
    if bit_length is None:
        bit_length = key_value.bit_length()

    print(f"\n{'=' * 60}")
    print(f"{key_type} Key Information:")
    print(f"{'=' * 60}")
    print(f"Bit Length: {bit_length} bits")
    print(f"Hex Value: {format_hex(key_value)}")
    print(f"Decimal: {key_value}")
    print(f"{'=' * 60}\n")
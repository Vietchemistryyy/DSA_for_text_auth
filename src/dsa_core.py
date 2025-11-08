"""
DSA Core - Triển khai thuật toán DSA cơ bản
"""
import secrets
from typing import Tuple
from .utils import mod_inverse, validate_dsa_params


class DSACore:
    """
    Lớp triển khai thuật toán DSA (Digital Signature Algorithm)
    """

    # Tham số DSA chuẩn (1024-bit)
    # Đây là tham số từ FIPS 186-4
    DEFAULT_P = int(
        "FD7F53811D75122952DF4A9C2EECE4E7F611B7523CEF4400C31E3F80B6512669"
        "455D402251FB593D8D58FABFC5F5BA30F6CB9B556CD7813B801D346FF26660B7"
        "6B9950A5A49F9FE8047B1022C24FBBA9D7FEB7C61BF83B57E7C6A8A6150F04FB"
        "83F6D3C51EC3023554135A169132F675F3AE2B61D72AEFF22203199DD14801C7", 16
    )

    DEFAULT_Q = int(
        "9760508F15230BCCB292B982A2EB840BF0581CF5", 16
    )

    DEFAULT_G = int(
        "F7E1A085D69B3DDECBBCAB5C36B857B97994AFBBFA3AEA82F9574C0B3D078267"
        "5159578EBAD4594FE67107108180B449167123E84C281613B7CF09328CC8A6E1"
        "3C167A8B547C8D28E0A3AE1E2BB3A675916EA37F0BFA213562F1FB627A01243B"
        "CCA4F1BEA8519089A883DFE15AE59F06928B665E807B552564014C3BFECF492A", 16
    )

    def __init__(self, p: int = None, q: int = None, g: int = None):
        """
        Khởi tạo DSA với các tham số

        Args:
            p: Số nguyên tố lớn (mặc định sử dụng tham số chuẩn)
            q: Số nguyên tố nhỏ, ước của (p-1)
            g: Generator với order q trong Z*p
        """
        self.p = p if p is not None else self.DEFAULT_P
        self.q = q if q is not None else self.DEFAULT_Q
        self.g = g if g is not None else self.DEFAULT_G

        # Kiểm tra tính hợp lệ của tham số
        if not validate_dsa_params(self.p, self.q, self.g):
            raise ValueError("Tham số DSA không hợp lệ!")

    def generate_private_key(self) -> int:
        """
        Tạo private key ngẫu nhiên

        Returns:
            int: Private key x trong khoảng (1, q-1)
        """
        return secrets.randbelow(self.q - 1) + 1

    def generate_public_key(self, private_key: int) -> int:
        """
        Tạo public key từ private key

        Args:
            private_key: Private key x

        Returns:
            int: Public key y = g^x mod p
        """
        if not (1 <= private_key < self.q):
            raise ValueError("Private key phải nằm trong khoảng (1, q-1)")

        return pow(self.g, private_key, self.p)

    def generate_key_pair(self) -> Tuple[int, int]:
        """
        Tạo cặp khóa DSA (private, public)

        Returns:
            Tuple[int, int]: (private_key, public_key)
        """
        private_key = self.generate_private_key()
        public_key = self.generate_public_key(private_key)
        return private_key, public_key

    def sign(self, message_hash: int, private_key: int) -> Tuple[int, int]:
        """
        Ký message hash sử dụng private key

        Args:
            message_hash: Hash của message (số nguyên)
            private_key: Private key x

        Returns:
            Tuple[int, int]: Chữ ký (r, s)

        Raises:
            ValueError: Nếu không tạo được chữ ký hợp lệ
        """
        if not (1 <= private_key < self.q):
            raise ValueError("Private key không hợp lệ")

        # Thử tạo chữ ký, retry nếu r hoặc s = 0
        max_attempts = 100
        for _ in range(max_attempts):
            # Bước 1: Chọn k ngẫu nhiên trong (1, q-1)
            k = secrets.randbelow(self.q - 1) + 1

            # Bước 2: Tính r = (g^k mod p) mod q
            r = pow(self.g, k, self.p) % self.q

            if r == 0:
                continue

            # Bước 3: Tính s = k^-1 * (H(m) + x*r) mod q
            try:
                k_inv = mod_inverse(k, self.q)
                s = (k_inv * (message_hash + private_key * r)) % self.q

                if s == 0:
                    continue

                return (r, s)
            except ValueError:
                continue

        raise ValueError("Không thể tạo chữ ký hợp lệ sau nhiều lần thử")

    def verify(self, message_hash: int, signature: Tuple[int, int],
               public_key: int) -> bool:
        """
        Xác thực chữ ký

        Args:
            message_hash: Hash của message (số nguyên)
            signature: Chữ ký (r, s)
            public_key: Public key y

        Returns:
            bool: True nếu chữ ký hợp lệ
        """
        r, s = signature

        # Kiểm tra điều kiện cơ bản
        if not (0 < r < self.q and 0 < s < self.q):
            return False

        try:
            # Bước 1: Tính w = s^-1 mod q
            w = mod_inverse(s, self.q)

            # Bước 2: Tính u1 = H(m) * w mod q
            u1 = (message_hash * w) % self.q

            # Bước 3: Tính u2 = r * w mod q
            u2 = (r * w) % self.q

            # Bước 4: Tính v = ((g^u1 * y^u2) mod p) mod q
            v = (pow(self.g, u1, self.p) * pow(public_key, u2, self.p)) % self.p % self.q

            # Bước 5: So sánh v với r
            return v == r

        except ValueError:
            return False

    def get_params(self) -> dict:
        """
        Lấy thông tin các tham số DSA

        Returns:
            dict: Dictionary chứa p, q, g
        """
        return {
            'p': self.p,
            'q': self.q,
            'g': self.g,
            'p_bits': self.p.bit_length(),
            'q_bits': self.q.bit_length()
        }

    def __str__(self) -> str:
        """String representation của DSA"""
        params = self.get_params()
        return (f"DSA Core\n"
                f"  p: {params['p_bits']} bits\n"
                f"  q: {params['q_bits']} bits\n"
                f"  g: {params['g_bits'] if 'g_bits' in params else self.g.bit_length()} bits")

"""
DSA Digital Signature Package
Hệ thống chữ ký số DSA cho xác thực văn bản
"""

__version__ = "1.0.0"
__author__ = "DSA Signature Team"

from .dsa_core import DSACore
from .key_manager import KeyManager
from .signature import DSASignature
from .utils import hash_message, bytes_to_int, int_to_bytes

__all__ = [
    'DSACore',
    'KeyManager',
    'DSASignature',
    'hash_message',
    'bytes_to_int',
    'int_to_bytes'
]
"""
File Reader - Đọc nội dung từ nhiều loại file
"""
import io
from pathlib import Path


def read_file_content(file_obj, filename: str = None) -> tuple[str, bool]:
    """
    Đọc nội dung file từ nhiều định dạng
    
    Args:
        file_obj: File object hoặc bytes
        filename: Tên file (để xác định extension)
    
    Returns:
        tuple[str, bool]: (content, is_text_file)
            - content: Nội dung file dạng text
            - is_text_file: True nếu là file text thuần, False nếu đã extract từ binary
    """
    if filename:
        filename_lower = filename.lower()
    else:
        filename_lower = ""
    
    # Đọc bytes từ file object
    if hasattr(file_obj, 'read'):
        file_bytes = file_obj.read()
        if hasattr(file_obj, 'seek'):
            file_obj.seek(0)  # Reset về đầu file
    else:
        file_bytes = file_obj
    
    # 1. Thử đọc như text file trước (txt, md, json, xml, csv, log, code files)
    text_extensions = ['.txt', '.md', '.json', '.xml', '.csv', '.log', 
                      '.py', '.js', '.html', '.css', '.java', '.c', '.cpp', '.h']
    
    if any(filename_lower.endswith(ext) for ext in text_extensions):
        try:
            content = file_bytes.decode('utf-8')
            # Normalize line endings để đảm bảo nhất quán
            # Chuyển tất cả về \n (Unix style)
            content = content.replace('\r\n', '\n').replace('\r', '\n')
            return content, True
        except UnicodeDecodeError:
            pass
    
    # 2. File .docx - Microsoft Word
    if filename_lower.endswith('.docx'):
        try:
            from docx import Document
            doc = Document(io.BytesIO(file_bytes))
            paragraphs = [para.text for para in doc.paragraphs]
            content = '\n'.join(paragraphs)
            return content, False
        except Exception as e:
            return f"[Không thể đọc file .docx: {str(e)}]", False
    
    # 3. File .pdf - PDF
    if filename_lower.endswith('.pdf'):
        try:
            from PyPDF2 import PdfReader
            pdf = PdfReader(io.BytesIO(file_bytes))
            pages_text = []
            for page in pdf.pages:
                pages_text.append(page.extract_text())
            content = '\n'.join(pages_text)
            return content, False
        except Exception as e:
            return f"[Không thể đọc file .pdf: {str(e)}]", False
    
    # 4. File .doc - Microsoft Word cũ (cần thư viện khác, tạm thời không hỗ trợ)
    if filename_lower.endswith('.doc'):
        return "[File .doc không được hỗ trợ. Vui lòng chuyển sang .docx hoặc .txt]", False
    
    # 5. Các file binary khác - thử decode UTF-8, nếu không được thì trả về hex
    try:
        content = file_bytes.decode('utf-8')
        # Normalize line endings
        content = content.replace('\r\n', '\n').replace('\r', '\n')
        return content, True
    except UnicodeDecodeError:
        # File binary không thể decode - trả về thông tin
        return f"[File binary: {len(file_bytes)} bytes - Không thể hiển thị nội dung text]", False


def get_file_preview(file_obj, filename: str = None, max_length: int = 300) -> str:
    """
    Lấy preview ngắn của file
    
    Args:
        file_obj: File object hoặc bytes
        filename: Tên file
        max_length: Độ dài tối đa của preview
    
    Returns:
        str: Preview content
    """
    content, is_text = read_file_content(file_obj, filename)
    
    if len(content) > max_length:
        return content[:max_length] + '...'
    return content

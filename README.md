# DSA Digital Signature System

## Bài toán

Xây dựng hệ thống chữ ký số để đảm bảo tính xác thực và toàn vẹn của văn bản/file:
- Người gửi ký văn bản bằng private key
- Người nhận xác thực chữ ký bằng public key
- Phát hiện nếu văn bản bị thay đổi sau khi ký
- Xác nhận người ký là chủ sở hữu private key

## Thuật toán DSA

DSA (Digital Signature Algorithm) là chuẩn chữ ký số của NIST (FIPS 186):

**Tạo khóa:**
- Chọn số nguyên tố p, q (q là ước của p-1)
- Tính g = h^((p-1)/q) mod p
- Private key: x (ngẫu nhiên, 0 < x < q)
- Public key: y = g^x mod p

**Ký:**
- Hash văn bản: H = SHA-256(message)
- Chọn k ngẫu nhiên (0 < k < q)
- r = (g^k mod p) mod q
- s = (k^-1 × (H + x×r)) mod q
- Chữ ký: (r, s)

**Xác thực:**
- Hash văn bản: H = SHA-256(message)
- w = s^-1 mod q
- u1 = (H × w) mod q
- u2 = (r × w) mod q
- v = ((g^u1 × y^u2) mod p) mod q
- Hợp lệ nếu v = r

## Kiến trúc

```
Người ký                    Người xác thực
   |                              |
   | 1. Tạo cặp khóa              |
   |    (private, public)         |
   |                              |
   | 2. Ký văn bản                |
   |    → Chữ ký (r,s)            |
   |                              |
   | 3. Gửi (văn bản, chữ ký, public key)
   |----------------------------->|
                                  |
                            4. Xác thực
                               → True/False
```

## Cách hệ thống DSA hoạt động

Phần này mô tả **luồng hoạt động thực tế** của một hệ thống chữ ký số dùng DSA, từ lúc tạo khóa đến lúc ký và xác thực.

### 1. Tạo và quản lý cặp khóa

1. **Tạo khóa**  
   - Hệ thống sinh ra một cặp khóa DSA:  
     - `private key (x)` – chỉ chủ sở hữu biết.  
     - `public key (y)` – có thể gửi cho bất kỳ ai cần xác thực chữ ký.  
   - Việc sinh khóa dựa trên các tham số (p, q, g) và sinh số ngẫu nhiên x như phần "Tạo khóa" đã mô tả ở trên.

2. **Lưu trữ khóa**  
   - **Private key** phải được lưu ở nơi an toàn (trong hệ thống của người ký, không chia sẻ ra ngoài).  
   - **Public key** có thể lưu trong file, trong cơ sở dữ liệu, hoặc gửi kèm cho người nhận.  
   - Trong một ứng dụng thực tế, thường sẽ có:
     - Một lớp/quản lý (`KeyManager`) chịu trách nhiệm tạo, giữ và cung cấp khóa cho các thao tác ký/xác thực.  
     - Các API hoặc chức năng cho phép export/import public key để chia sẻ cho người khác.

3. **Trạng thái khóa trong hệ thống**  
   - Hệ thống luôn cần biết:  
     - Đã có **private key** hay chưa (mới tạo hay chưa)?  
     - Đã có **public key** hay chưa (đã export cho người khác dùng chưa)?  
   - Từ đó, giao diện hoặc backend có thể:
     - Cho phép người dùng tạo khóa mới.  
     - Cho phép xóa toàn bộ khóa hiện tại.  
     - Cho phép export/import khóa khi cần.

### 2. Quy trình ký văn bản

Giả sử hệ thống đã có private key hợp lệ.

1. **Người dùng nhập văn bản**  
   - Người dùng nhập nội dung cần ký (message) vào hệ thống (web, API, ứng dụng…).

2. **Tiền xử lý & băm (hash)**  
   - Hệ thống không ký trực tiếp trên chuỗi văn bản, mà:
     - Chuyển văn bản sang dạng bytes.  
     - Tính `H = SHA-256(message)` để thu được giá trị băm cố định độ dài.  
   - Việc này giúp:
     - Bảo đảm xử lý được cả dữ liệu rất lớn.  
     - Tăng bảo mật nhờ thuộc tính một chiều của hàm hash.

3. **Tạo chữ ký DSA**  
   - Hệ thống dùng private key `x` và sinh số ngẫu nhiên bí mật `k` (0 < k < q).  
   - Tính:
     - `r = (g^k mod p) mod q`  
     - `s = (k^-1 × (H + x×r)) mod q`  
   - Cặp `(r, s)` chính là **chữ ký số** cho văn bản đó.

4. **Trả về kết quả ký**  
   - Hệ thống trả về cho người dùng:
     - Văn bản gốc (message).  
     - Chữ ký `(r, s)` (thường ở dạng hex).  
     - Public key (nếu cần gửi kèm cho người nhận).
   - Trong ứng dụng thực tế, chữ ký có thể được:
     - Hiển thị trên màn hình.  
     - Lưu thành file (ví dụ `.sig` hoặc `.json`).  
     - Gửi đi qua mạng cùng với văn bản.

### 3. Gửi cho người nhận

Để người nhận có thể kiểm tra được chữ ký, họ cần **đủ 3 thông tin**:

1. Văn bản gốc (message).  
2. Chữ ký `(r, s)`.  
3. Public key `y` (của người ký).

Ba thứ này có thể được gửi:
- Trong cùng một gói dữ liệu (file, JSON, request API,…).  
- Hoặc public key được gửi/trao đổi từ trước (ví dụ lưu sẵn trong hệ thống tin cậy).

### 4. Quy trình xác thực chữ ký

Ở phía người nhận (hoặc hệ thống xác thực), các bước như sau:

1. **Nhận dữ liệu**  
   - Hệ thống nhận:
     - `message` – văn bản gốc.  
     - `r, s` – hai tham số của chữ ký.  
     - `y` – public key của người được cho là đã ký.

2. **Băm lại văn bản**  
   - Hệ thống tự tính lại: `H' = SHA-256(message)`  
   - Nếu message đã bị chỉnh sửa, `H'` sẽ khác với giá trị dùng khi ký ban đầu.

3. **Tính các giá trị trung gian**  
   - Tính:  
     - `w = s^-1 mod q`  
     - `u1 = (H' × w) mod q`  
     - `u2 = (r × w) mod q`  
   - Sau đó tính:  
     - `v = ((g^u1 × y^u2) mod p) mod q`

4. **So sánh v với r**  
   - Nếu `v = r` → chữ ký **hợp lệ**:  
     - Văn bản chưa bị thay đổi kể từ lúc ký.  
     - Người sở hữu private key tương ứng với public key `y` đã tạo ra chữ ký.
   - Nếu `v ≠ r` → chữ ký **không hợp lệ**:  
     - Hoặc văn bản đã bị thay đổi.  
     - Hoặc chữ ký/khóa công khai không khớp.  
     - Hoặc chữ ký bị giả mạo.

### 5. Tóm tắt luồng hệ thống

1. **Người ký**:
   - Tạo cặp khóa `(private, public)`.  
   - Nhập văn bản cần ký.  
   - Hệ thống dùng **private key** để tạo chữ ký `(r, s)`.  
   - Gửi `message + (r, s) + public key` cho người nhận.

2. **Người xác thực**:
   - Nhận `message`, `(r, s)`, `public key`.  
   - Dùng **public key** để kiểm tra lại chữ ký theo các bước DSA.  
   - Kết luận: **Hợp lệ / Không hợp lệ**.

Toàn bộ quy trình trên có thể được triển khai qua giao diện web, API hoặc ứng dụng dòng lệnh, nhưng về bản chất luôn tuân theo đúng các bước toán học của DSA như đã mô tả.

## Tác giả

**Nguyễn Quốc Việt**

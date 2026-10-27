# Talky - ứng dụng chat realtime

Web chat kiểu Messenger. Backend (Flask + Flask-SocketIO + SQLite) phục vụ luôn cả giao diện, nên chỉ cần chạy **một server** và dùng **một địa chỉ** duy nhất. Nhờ vậy chạy được trên localhost, cùng wifi, hoặc qua Internet (wifi khác, 4G/5G).

```
talky/
├── backend/            API + WebSocket + phục vụ giao diện
│   ├── app.py
│   └── requirements.txt
└── frontend/           Giao diện (HTML + Tailwind + JS thuần)
    ├── index.html
    ├── app.js
    ├── config.js
    └── logo.svg
```

## 1. Cài đặt (làm một lần)
Cần Python 3.9 trở lên.
```
cd backend
pip install -r requirements.txt
```

## 2. Chạy trên máy mình
```
cd backend
python app.py
```
Mở **http://localhost:5000/web/** (nhớ có `/web/` ở cuối).
Dùng cửa sổ thường và cửa sổ ẩn danh để đăng nhập 2 tài khoản khác nhau.
Cần Internet để tải Tailwind, font và Socket.IO client từ CDN.

## 3. Chạy cho bạn bè dùng 4G/5G hoặc wifi khác
`localhost` và IP kiểu `192.168.x.x` chỉ dùng được trong cùng mạng. Để điện thoại dùng 4G/5G vào được, cần đưa server ra Internet bằng **tunnel** (không cần mở port router, hợp với mạng di động và CGNAT).

**Bước 1.** Mở terminal thứ nhất, chạy backend ở chế độ công khai (PowerShell):
```
cd backend
$env:PUBLIC="1"; $env:SECRET_KEY="doi-thanh-chuoi-bi-mat-cua-ban"; python app.py
```
Trên macOS/Linux:
```
PUBLIC=1 SECRET_KEY="doi-thanh-chuoi-bi-mat-cua-ban" python app.py
```

**Bước 2.** Mở terminal thứ hai, chạy một trong hai tunnel:
```
cloudflared tunnel --url http://localhost:5000
```
hoặc
```
ngrok http 5000
```
Cloudflared không cần tài khoản. Nó in ra link dạng `https://xxxx.trycloudflare.com`.

**Bước 3.** Gửi cho bạn bè link:
```
https://xxxx.trycloudflare.com/web/
```
Wifi, 4G hay 5G đều mở được, trên cả điện thoại và máy tính.

Lưu ý:
- Máy bạn phải bật và cả 2 terminal phải chạy suốt thì mọi người mới vào được.
- Link tunnel miễn phí **đổi mỗi lần chạy lại**, phải gửi link mới.
- Frontend và backend cùng một địa chỉ nên cookie đăng nhập hoạt động bình thường, kể cả iPhone/Safari.
- `PUBLIC=1` cho phép Socket.IO nhận kết nối từ mọi địa chỉ. Chỉ dùng khi chạy qua tunnel và luôn đặt `SECRET_KEY` riêng.
- Link tunnel là công khai, ai có link đều đăng ký được tài khoản. Đừng đăng link lên nơi công cộng.

## 4. Chạy cùng wifi (không cần tunnel)
Giả sử IP máy bạn là 192.168.1.5 (xem bằng `ipconfig`), PowerShell:
```
$env:HOST="0.0.0.0"; $env:PUBLIC="1"; python app.py
```
Bạn bè cùng wifi mở **http://192.168.1.5:5000/web/**. Có thể phải cho phép Python qua Windows Firewall.

## 5. Chạy lâu dài (deploy)
Tunnel chỉ hợp để thử. Muốn chạy ổn định, thuê VPS (hoặc Railway, Render...) và lưu ý:
- Chạy **1 worker**, vì Socket.IO cần vậy nếu không có Redis.
- Database `backend/instance/talky.db` và ảnh trong `backend/static/uploads` phải nằm trên ổ đĩa lưu lâu dài (volume), nhiều host miễn phí sẽ xóa khi khởi động lại.
- Đặt `SECRET_KEY` thật, dùng HTTPS (Caddy hoặc Nginx + Let's Encrypt).
- Nên tắt `debug=True` ở cuối `app.py` khi chạy thật.

## Biến môi trường (backend)
| Biến | Mặc định | Ý nghĩa |
|---|---|---|
| `PUBLIC` | không đặt | Đặt `1` để Socket.IO nhận mọi địa chỉ truy cập, cần khi chạy qua tunnel hoặc IP wifi |
| `SECRET_KEY` | chuỗi mẫu | Khóa ký phiên đăng nhập, **bắt buộc đổi** khi đưa lên mạng |
| `HOST` | 127.0.0.1 | Đặt `0.0.0.0` để máy khác trong wifi truy cập |
| `FRONTEND_ORIGINS` | localhost và 127.0.0.1, cổng 3000 và 8000 | Chỉ cần khi chạy frontend tách riêng ở server khác, cách nhau bằng dấu phẩy |
| `COOKIE_SAMESITE` | Lax | Đặt `None` (cần HTTPS) chỉ khi frontend và backend khác tên miền |

## Xử lý lỗi thường gặp
- **Mở link thấy `{"app":"Talky API","status":"ok"}`**: thiếu `/web/` ở cuối địa chỉ.
- **Đăng nhập được nhưng không nhắn realtime, console báo lỗi CORS/WebSocket**: chưa đặt `PUBLIC=1` khi chạy backend.
- **Bạn bè báo link không vào được**: kiểm tra tunnel còn chạy không, hoặc link đã đổi do chạy lại.
- **Đăng nhập xong bị văng ra**: đang mở frontend và backend bằng hai tên khác nhau (ví dụ một bên `localhost`, một bên `127.0.0.1`). Hãy dùng đúng một địa chỉ.

## Tính năng
- Đăng ký / đăng nhập (mật khẩu băm, phiên bằng cookie)
- Tìm người, gửi và chấp nhận lời mời kết bạn; chỉ bạn bè mới nhắn được cho nhau
- Chat 1-1 và chat nhóm, realtime, lưu lịch sử trong SQLite, tải thêm tin cũ
- Gửi ảnh (png, jpg, gif, webp, tối đa 5MB)
- Online/offline, "đang nhập...", đã gửi / đã xem, số tin chưa đọc
- Emoji, âm báo tin mới, chế độ sáng/tối, dùng được trên điện thoại

Nếu nâng cấp từ bản cũ, hãy xóa file `backend/instance/talky.db` để database được tạo lại.

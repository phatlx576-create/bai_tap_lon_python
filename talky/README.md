# Talky - ứng dụng chat realtime

Web chat kiểu Messenger, tách riêng backend và frontend.

```
talky/
├── backend/            API + WebSocket (Flask, Flask-SocketIO, SQLite)
│   ├── app.py
│   └── requirements.txt
└── frontend/           Giao diện (HTML + Tailwind + JS thuần)
    ├── index.html
    ├── app.js
    ├── config.js       Địa chỉ backend
    └── logo.svg
```

## Chạy thử (mở 2 terminal)
Terminal 1, backend (cổng 5000):
```
cd backend
pip install -r requirements.txt
python app.py
```
Terminal 2, frontend (cổng 3000):
```
cd frontend
python -m http.server 3000
```
Mở http://localhost:3000. Dùng cửa sổ thường và cửa sổ ẩn danh để đăng nhập 2 tài khoản khác nhau.
Cần Internet để tải Tailwind, font và Socket.IO client từ CDN.

## Cách hai phần nói chuyện với nhau
- Frontend gọi REST API (`/api/...`) và kết nối Socket.IO tới backend, kèm cookie đăng nhập.
- Backend bật CORS cho các địa chỉ trong biến `FRONTEND_ORIGINS` (mặc định `http://localhost:3000` và `http://127.0.0.1:3000`).
- Ảnh được lưu ở `backend/static/uploads` và frontend hiển thị bằng địa chỉ backend.
- Hãy mở frontend bằng cùng một tên máy với backend (cùng `localhost` hoặc cùng `127.0.0.1`) để cookie hoạt động.

## Biến môi trường (backend)
| Biến | Mặc định | Ý nghĩa |
|---|---|---|
| `SECRET_KEY` | chuỗi mẫu | Khóa ký phiên đăng nhập, hãy đổi khi đưa lên mạng |
| `FRONTEND_ORIGINS` | localhost và 127.0.0.1, cổng 3000 và 8000 | Các địa chỉ frontend được phép, cách nhau bằng dấu phẩy |
| `HOST` | 127.0.0.1 | Đặt `0.0.0.0` để máy khác trong wifi truy cập |
| `COOKIE_SAMESITE` | Lax | Đặt `None` (cần HTTPS) nếu frontend và backend khác tên miền |

## Chạy cho bạn cùng wifi
Giả sử IP máy bạn là 192.168.1.5:
```
HOST=0.0.0.0 FRONTEND_ORIGINS=http://192.168.1.5:3000 python app.py     (backend)
python -m http.server 3000                                                (frontend)
```
Bạn bè mở http://192.168.1.5:3000. Trên Windows PowerShell, đặt biến bằng `$env:HOST="0.0.0.0"; $env:FRONTEND_ORIGINS="http://192.168.1.5:3000"` trước khi chạy.

## Tính năng
- Đăng ký / đăng nhập (mật khẩu băm, phiên bằng cookie)
- Tìm người, gửi và chấp nhận lời mời kết bạn; chỉ bạn bè mới nhắn được cho nhau
- Chat 1-1 và chat nhóm, realtime, lưu lịch sử trong SQLite, tải thêm tin cũ
- Gửi ảnh (png, jpg, gif, webp, tối đa 5MB)
- Online/offline, "đang nhập...", đã gửi / đã xem, số tin chưa đọc
- Emoji, âm báo tin mới, chế độ sáng/tối, dùng được trên điện thoại

Nếu nâng cấp từ bản cũ, hãy xóa file `backend/instance/talky.db` để database được tạo lại.

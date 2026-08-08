# DAILY REPORT v6 — Login Email + OTP

Versi ini mewajibkan pengguna masuk menggunakan email dan kode OTP 6 digit.
OTP dikirim oleh akun Gmail yang dikonfigurasi pada `SMTP_USER` (default: mariohebat7@gmail.com).

## Penting
Jangan pernah memasukkan password Gmail biasa ke HTML/JavaScript. Gunakan **Google App Password** di server melalui file `.env`.

## Menjalankan lokal
1. Install Node.js 18+.
2. Buka folder proyek di Terminal.
3. Jalankan `npm install`.
4. Salin `.env.example` menjadi `.env`.
5. Pada akun `mariohebat7@gmail.com`, aktifkan Verifikasi 2 Langkah lalu buat **App Password** untuk aplikasi ini.
6. Masukkan App Password tersebut ke `SMTP_PASS` di `.env`.
7. Ganti `SESSION_SECRET` dan `OTP_PEPPER` dengan string acak panjang dan berbeda.
8. Jalankan `npm start`.
9. Buka `http://localhost:3000`.

## Alur akses
- Pengguna mengisi email.
- Server mengirim OTP 6 digit ke email pengguna dari `mariohebat7@gmail.com`.
- OTP berlaku 10 menit, maksimal 5 percobaan.
- Setelah OTP benar, email otomatis tercatat sebagai akun dan sesi login dibuat selama maksimal 7 hari.
- Tombol Keluar tersedia di sidebar aplikasi.

## Deployment
Hosting harus mendukung Node.js/Express dan HTTPS. Jangan mengunggah file `.env` ke repository publik.
Untuk penggunaan banyak user/produksi, gunakan session store persisten (mis. Redis) menggantikan MemoryStore bawaan Express.

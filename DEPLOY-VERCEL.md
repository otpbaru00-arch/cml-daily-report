# Deploy DAILY REPORT ke Vercel

Project ini sudah disiapkan untuk Vercel Serverless Functions.

## 1. Gmail untuk OTP
Pengirim OTP:

`mariohebat7@gmail.com`

Jangan gunakan password Gmail biasa. Buat **Google App Password** untuk akun tersebut (2-Step Verification harus aktif).

## 2. Environment Variables di Vercel
Tambahkan 4 variable berikut untuk Production, Preview, dan Development bila diperlukan:

- `SMTP_USER` = `mariohebat7@gmail.com`
- `SMTP_PASS` = Google App Password 16 karakter
- `SESSION_SECRET` = random string panjang, minimal 32 karakter
- `OTP_PEPPER` = random string lain, minimal 32 karakter

Jangan masukkan App Password ke file HTML dan jangan mengirimkannya melalui chat.

## 3. Deploy
Import folder/project ini ke Vercel. Vercel akan mendeteksi `vercel.json` dan function `api/router.js`.

Setelah deploy:

- `/login` = halaman login OTP
- `/` = aplikasi utama, terlindungi sesi login
- `/health` = health check sederhana

## 4. Cara kerja auth di Vercel
Versi serverless tidak menyimpan OTP di RAM atau file server. OTP disimpan sebagai hash yang ditandatangani di cookie HttpOnly berumur 10 menit, lalu sesi login ditandatangani selama 7 hari. Hal ini cocok dengan runtime serverless Vercel.

## 5. Catatan penyimpanan report
Data report pada versi ini masih memakai localStorage browser, sesuai aplikasi sebelumnya. Artinya data report tersimpan di browser/perangkat yang menginputnya dan belum menjadi database bersama lintas perangkat/user.

Jika dibutuhkan penggunaan multi-user dengan data report yang sama di semua perangkat, tahap berikutnya adalah memindahkan data report ke database cloud (Postgres/Neon/Supabase/Vercel Postgres) dan menambahkan role/permission akun.


## Catatan v11
Konfigurasi `functions.api/router.js.includeFiles` menggunakan string glob `**/*.html` sesuai format Vercel. Ini memperbaiki error build `Invalid vercel.json - functions[api/router.js]`.

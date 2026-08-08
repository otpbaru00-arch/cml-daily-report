# CML Daily Report v12 — Cloud Database

Versi ini menggunakan PostgreSQL/Supabase yang terhubung dari Vercel.

Environment variable database yang didukung backend:
- POSTGRES_URL
- STORAGE_POSTGRES_URL
- DATABASE_URL
- STORAGE_URL

Autentikasi tetap membutuhkan:
- SMTP_USER
- SMTP_PASS
- SESSION_SECRET
- OTP_PEPPER

## Cara kerja sinkronisasi

Frontend lama tetap menggunakan struktur data yang sama agar semua fitur tetap kompatibel. Backend melakukan sinkronisasi ke tabel Supabase:
- new_depo_assets / new_depo_periods / new_depo_rows
- daily_assets / daily_report_entries
- annul_entries
- report_settings
- app_users

Saat halaman dibuka, data cloud dimuat ke aplikasi. Jika database masih kosong tetapi browser memiliki data lama, data browser akan dimigrasikan otomatis ke cloud setelah login.

Status sinkronisasi muncul di kotak akun pada sidebar:
- Cloud tersambung
- Menyimpan ke cloud
- Cloud tersimpan
- Cloud gagal menyimpan

Catatan: model sinkronisasi v12 adalah last-write-wins per kategori report. Hindari dua pengguna mengedit kategori report yang sama secara bersamaan sampai mode kolaborasi granular ditambahkan.

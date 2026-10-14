# FORKT Key Service

Backend + halaman GET KEY untuk importer milik sendiri. Target deployment: Cloudflare Workers + D1.
Repository tujuan yang disarankan: `https://github.com/dancok1238/forkt-key-service`

## Fitur
- Login Roblox OAuth 2.0 Authorization Code + PKCE.
- Satu key permanen per akun Roblox.
- Database hanya menyimpan SHA-256 key hash, bukan key asli.
- Verifikasi key untuk integrasi importer.
- Panel admin sederhana untuk melihat status dan mencabut key.
- Log audit untuk penerbitan dan pencabutan.
- Session cookie HttpOnly/Secure/SameSite=Lax.

## Penting sebelum dipakai
1. Buat aplikasi OAuth Roblox di Creator Dashboard dan daftarkan callback tepat:
   `https://NAMA-WORKER.SUBDOMAIN.workers.dev/auth/callback`
2. Aktifkan scope `openid profile`.
3. Jangan menaruh `ROBLOX_CLIENT_SECRET` atau `ADMIN_TOKEN` di GitHub, HTML, atau script Roblox.
4. Contoh integrasi importer tidak bisa membuat client-side Lua anti-tamper sempurna. Pengguna yang menguasai script lokal bisa mengubah pemeriksaan lokal; backend mengurangi pembagian key tetapi tidak membuat client yang dimodifikasi menjadi tepercaya.
5. Endpoint `/api/verify` memeriksa key aktif dan klaim `robloxUserId`. Klaim UserId dari script client dapat dipalsukan. Ini cocok sebagai gerbang akses dasar, bukan perlindungan lisensi yang tahan modifikasi.
6. Jangan menaruh key asli di GitHub, log, atau pesan publik.

## Deploy singkat (terminal dengan Node.js)
```bash
npm install
npx wrangler d1 create forkt-key-db
```
Salin `database_id` hasil perintah ke `wrangler.toml`, lalu:
```bash
npx wrangler d1 migrations apply forkt-key-db --remote
npx wrangler secret put ROBLOX_CLIENT_ID
npx wrangler secret put ROBLOX_CLIENT_SECRET
npx wrangler secret put ADMIN_TOKEN
npx wrangler deploy
```
`ROBLOX_CLIENT_ID` boleh juga dianggap bukan rahasia, tetapi disimpan sebagai secret agar konfigurasi konsisten. `ADMIN_TOKEN` gunakan token acak panjang minimal 32 karakter dan simpan di pengelola kata sandi.

## Pengaturan OAuth
- Redirect URI harus persis sama dengan `https://.../auth/callback`.
- Setelah Worker dideploy, buka URL Worker, login Roblox, lalu klik GET KEY.
- Untuk produksi, gunakan domain HTTPS milik sendiri jika tersedia.
- Endpoint admin menerima `Authorization: Bearer <ADMIN_TOKEN>`. Jangan membagikan token itu.

## Mengunggah ke GitHub
Buat repository kosong bernama `forkt-key-service` di akun `dancok1238`, lalu unggah semua isi folder ini. ZIP ini belum otomatis diunggah ke GitHub.

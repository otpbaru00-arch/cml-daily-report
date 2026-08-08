'use strict';
require('dotenv').config();
const express = require('express');
const session = require('express-session');
const nodemailer = require('nodemailer');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = Number(process.env.PORT || 3000);
const ROOT = __dirname;
const DATA_DIR = path.join(ROOT, 'data');
const USERS_FILE = path.join(DATA_DIR, 'users.json');
const SMTP_USER = process.env.SMTP_USER || 'mariohebat7@gmail.com';
const SMTP_PASS = process.env.SMTP_PASS || '';
const SESSION_SECRET = process.env.SESSION_SECRET || '';
const OTP_PEPPER = process.env.OTP_PEPPER || SESSION_SECRET;
const OTP_TTL = 10 * 60 * 1000;
const RESEND_DELAY = 60 * 1000;
const otpStore = new Map();

if (!SMTP_PASS || !SESSION_SECRET || !OTP_PEPPER) {
  console.error('Konfigurasi belum lengkap. Isi SMTP_PASS, SESSION_SECRET, dan OTP_PEPPER di file .env');
  process.exit(1);
}

fs.mkdirSync(DATA_DIR, { recursive: true });
if (!fs.existsSync(USERS_FILE)) fs.writeFileSync(USERS_FILE, '[]\n');

app.set('trust proxy', 1);
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: '20kb' }));
app.use(session({
  name: 'daily_report_sid',
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: 'lax',
    secure: process.env.NODE_ENV === 'production',
    maxAge: 7 * 24 * 60 * 60 * 1000
  }
}));

const requestLimiter = rateLimit({ windowMs: 10 * 60 * 1000, limit: 15, standardHeaders: true, legacyHeaders: false });
const verifyLimiter = rateLimit({ windowMs: 10 * 60 * 1000, limit: 30, standardHeaders: true, legacyHeaders: false });

const transporter = nodemailer.createTransport({ service: 'gmail', auth: { user: SMTP_USER, pass: SMTP_PASS } });
const emailRe = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const normalizeEmail = v => String(v || '').trim().toLowerCase();
const otpHash = (email, otp) => crypto.createHmac('sha256', OTP_PEPPER).update(`${email}:${otp}`).digest('hex');
const safeEqual = (a, b) => {
  const x = Buffer.from(String(a)); const y = Buffer.from(String(b));
  return x.length === y.length && crypto.timingSafeEqual(x, y);
};
function loadUsers(){ try { return JSON.parse(fs.readFileSync(USERS_FILE,'utf8')); } catch { return []; } }
function saveUsers(users){ fs.writeFileSync(USERS_FILE, JSON.stringify(users,null,2)+'\n'); }
function upsertUser(email){ const users=loadUsers(); const now=new Date().toISOString(); let u=users.find(x=>x.email===email); if(!u){u={email,createdAt:now,lastLoginAt:now};users.push(u)}else u.lastLoginAt=now; saveUsers(users); return u; }
function requireAuth(req,res,next){ if(req.session?.user?.email) return next(); return res.redirect('/login'); }

app.get('/login', (req,res) => { if(req.session?.user?.email) return res.redirect('/'); res.sendFile(path.join(ROOT,'login.html')); });
app.get('/api/auth/session', (req,res) => res.json({ authenticated: !!req.session?.user?.email, user: req.session?.user || null }));

app.post('/api/auth/request-otp', requestLimiter, async (req,res) => {
  const email = normalizeEmail(req.body?.email);
  if(!emailRe.test(email)) return res.status(400).json({error:'Format email tidak valid.'});
  const prior = otpStore.get(email);
  const now = Date.now();
  if(prior && prior.nextSendAt > now) {
    const seconds = Math.ceil((prior.nextSendAt-now)/1000);
    return res.status(429).json({error:`Tunggu ${seconds} detik sebelum meminta OTP baru.`});
  }
  const otp = String(crypto.randomInt(0, 1000000)).padStart(6,'0');
  otpStore.set(email,{ hash:otpHash(email,otp), expiresAt:now+OTP_TTL, nextSendAt:now+RESEND_DELAY, attempts:0 });
  try{
    await transporter.sendMail({
      from: `DAILY REPORT <${SMTP_USER}>`,
      to: email,
      subject: 'Kode OTP Daily Report',
      text: `Kode OTP Anda: ${otp}\n\nKode berlaku 10 menit. Jangan berikan kode ini kepada orang lain.`,
      html: `<div style="font-family:Arial,sans-serif;max-width:520px;margin:auto"><h2>DAILY REPORT</h2><p>Gunakan kode OTP berikut untuk masuk:</p><div style="font-size:32px;font-weight:800;letter-spacing:8px;padding:16px;background:#f2f6fa;border-radius:10px;text-align:center">${otp}</div><p>Kode berlaku selama 10 menit.</p><p style="color:#667085;font-size:12px">Jangan berikan kode ini kepada siapa pun.</p></div>`
    });
    return res.json({message:`OTP telah dikirim ke ${email}.`});
  }catch(err){
    otpStore.delete(email);
    console.error('Gagal kirim email:', err.message);
    return res.status(500).json({error:'OTP gagal dikirim. Periksa konfigurasi email server.'});
  }
});

app.post('/api/auth/verify-otp', verifyLimiter, (req,res) => {
  const email=normalizeEmail(req.body?.email); const otp=String(req.body?.otp||'').replace(/\D/g,'');
  if(!emailRe.test(email) || otp.length!==6) return res.status(400).json({error:'Email atau OTP tidak valid.'});
  const rec=otpStore.get(email);
  if(!rec) return res.status(400).json({error:'OTP tidak ditemukan. Silakan minta kode baru.'});
  if(Date.now()>rec.expiresAt){otpStore.delete(email);return res.status(400).json({error:'OTP sudah kedaluwarsa. Silakan minta kode baru.'})}
  rec.attempts += 1;
  if(rec.attempts>5){otpStore.delete(email);return res.status(429).json({error:'Terlalu banyak percobaan. Silakan minta OTP baru.'})}
  if(!safeEqual(rec.hash,otpHash(email,otp))) return res.status(400).json({error:`OTP salah. Sisa percobaan: ${5-rec.attempts}.`});
  otpStore.delete(email);
  upsertUser(email);
  req.session.regenerate(err=>{
    if(err) return res.status(500).json({error:'Gagal membuat sesi login.'});
    req.session.user={email};
    req.session.save(err2=>err2?res.status(500).json({error:'Gagal menyimpan sesi.'}):res.json({ok:true,user:{email}}));
  });
});

app.post('/api/auth/logout', (req,res) => {
  if(!req.session) return res.json({ok:true});
  req.session.destroy(()=>{res.clearCookie('daily_report_sid');res.json({ok:true})});
});

app.get('/', requireAuth, (req,res) => res.sendFile(path.join(ROOT,'index.html')));
app.get('/index.html', requireAuth, (req,res) => res.sendFile(path.join(ROOT,'index.html')));

app.use((req,res)=>res.status(404).send('Not Found'));
app.listen(PORT, ()=>console.log(`Daily Report berjalan di http://localhost:${PORT}`));

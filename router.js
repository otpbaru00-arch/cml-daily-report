'use strict';

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const nodemailer = require('nodemailer');
const { Pool } = require('pg');

const SMTP_USER = process.env.SMTP_USER || 'mariohebat7@gmail.com';
const SMTP_PASS = process.env.SMTP_PASS || '';
const SESSION_SECRET = process.env.SESSION_SECRET || '';
const OTP_PEPPER = process.env.OTP_PEPPER || SESSION_SECRET;
const DATABASE_URL = process.env.POSTGRES_URL || process.env.STORAGE_POSTGRES_URL || process.env.DATABASE_URL || process.env.STORAGE_URL || '';

const OTP_TTL_MS = 10 * 60 * 1000;
const RESEND_DELAY_MS = 60 * 1000;
const SESSION_TTL_MS = 7 * 24 * 60 * 60 * 1000;
const SESSION_COOKIE = 'daily_report_session';
const OTP_COOKIE = 'daily_report_otp';

const ROOT = path.resolve(process.cwd());
const APP_HTML = path.join(ROOT, 'index.html');
const LOGIN_HTML = path.join(ROOT, 'login.html');

const TRACKED_KEYS = [
  'daily-report-new-depo:v2',
  'daily-report-assets:v1',
  'daily-report-annul:v1',
  'daily-report-results-settings:v1'
];

const emailRe = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const normalizeEmail = (v) => String(v || '').trim().toLowerCase();
const b64url = (input) => Buffer.from(input).toString('base64url');
const fromB64url = (input) => Buffer.from(input, 'base64url').toString('utf8');
const isUuid = (v) => /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(String(v || ''));
const upper = (v) => String(v ?? '').trim().toLocaleUpperCase('id-ID');

let pool;
function db() {
  if (!DATABASE_URL) return null;
  if (!pool) {
    pool = new Pool({
      connectionString: DATABASE_URL,
      ssl: DATABASE_URL.includes('localhost') ? false : { rejectUnauthorized: false },
      max: 3,
      idleTimeoutMillis: 10000,
      connectionTimeoutMillis: 10000
    });
  }
  return pool;
}

function hmac(value, secret) {
  return crypto.createHmac('sha256', secret).update(value).digest('base64url');
}
function signPayload(payload, secret) {
  const encoded = b64url(JSON.stringify(payload));
  return `${encoded}.${hmac(encoded, secret)}`;
}
function verifySignedPayload(token, secret) {
  try {
    const [encoded, sig] = String(token || '').split('.');
    if (!encoded || !sig) return null;
    const expected = hmac(encoded, secret);
    const a = Buffer.from(sig);
    const b = Buffer.from(expected);
    if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
    const payload = JSON.parse(fromB64url(encoded));
    return payload && typeof payload === 'object' ? payload : null;
  } catch (_) { return null; }
}
function parseCookies(req) {
  const header = req.headers.cookie || '';
  return header.split(';').reduce((acc, pair) => {
    const idx = pair.indexOf('=');
    if (idx < 0) return acc;
    const key = pair.slice(0, idx).trim();
    const val = pair.slice(idx + 1).trim();
    if (!key) return acc;
    try { acc[key] = decodeURIComponent(val); } catch { acc[key] = val; }
    return acc;
  }, {});
}
function cookie(name, value, opts = {}) {
  const parts = [`${name}=${encodeURIComponent(value)}`];
  parts.push(`Path=${opts.path || '/'}`);
  if (opts.maxAge !== undefined) parts.push(`Max-Age=${Math.max(0, Math.floor(opts.maxAge))}`);
  if (opts.httpOnly !== false) parts.push('HttpOnly');
  parts.push(`SameSite=${opts.sameSite || 'Lax'}`);
  if (opts.secure !== false) parts.push('Secure');
  return parts.join('; ');
}
function securityHeaders(res, html = false) {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'same-origin');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  res.setHeader('Cache-Control', 'no-store, max-age=0');
  if (html) {
    res.setHeader('Content-Security-Policy', "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'");
  }
}
function sendJson(res, status, obj, cookies = []) {
  securityHeaders(res, false);
  if (cookies.length) res.setHeader('Set-Cookie', cookies);
  res.statusCode = status;
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.end(JSON.stringify(obj));
}
function redirect(res, location, cookies = []) {
  securityHeaders(res, false);
  if (cookies.length) res.setHeader('Set-Cookie', cookies);
  res.statusCode = 302;
  res.setHeader('Location', location);
  res.end();
}
function serveHtml(res, file) {
  securityHeaders(res, true);
  res.statusCode = 200;
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.end(fs.readFileSync(file, 'utf8'));
}
function serveHtmlText(res, html) {
  securityHeaders(res, true);
  res.statusCode = 200;
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.end(html);
}
function bodyOf(req) {
  if (req.body && typeof req.body === 'object') return req.body;
  if (typeof req.body === 'string') {
    try { return JSON.parse(req.body); } catch { return {}; }
  }
  return {};
}
function getSession(req) {
  if (!SESSION_SECRET) return null;
  const cookies = parseCookies(req);
  const payload = verifySignedPayload(cookies[SESSION_COOKIE], SESSION_SECRET);
  if (!payload || payload.type !== 'session' || !payload.email || Date.now() > Number(payload.exp || 0)) return null;
  return payload;
}
function otpHash(email, otp) {
  return crypto.createHmac('sha256', OTP_PEPPER).update(`${email}:${otp}`).digest('base64url');
}
function safeEqualString(a, b) {
  const x = Buffer.from(String(a || ''));
  const y = Buffer.from(String(b || ''));
  return x.length === y.length && crypto.timingSafeEqual(x, y);
}
function routeFromReq(req) {
  const q = req.query || {};
  let route = Array.isArray(q.route) ? q.route[0] : q.route;
  route = String(route || '').replace(/^\/+/, '');
  return route || 'app';
}
function ensureConfig(res) {
  if (!SMTP_PASS || !SESSION_SECRET || !OTP_PEPPER) {
    sendJson(res, 503, { error: 'Konfigurasi server belum lengkap. Admin perlu mengisi environment variables Vercel.' });
    return false;
  }
  return true;
}
function safeParse(v, fallback = null) {
  if (typeof v !== 'string') return fallback;
  try { return JSON.parse(v); } catch { return fallback; }
}
function deepEqual(a, b) { return JSON.stringify(a) === JSON.stringify(b); }

async function q(client, text, params = []) { return client.query(text, params); }
async function withTx(fn) {
  const p = db();
  if (!p) throw new Error('DATABASE_NOT_CONFIGURED');
  const c = await p.connect();
  try {
    await c.query('begin');
    const out = await fn(c);
    await c.query('commit');
    return out;
  } catch (e) {
    try { await c.query('rollback'); } catch (_) {}
    throw e;
  } finally { c.release(); }
}

async function upsertLoginUser(email) {
  const p = db(); if (!p) return;
  await p.query(`insert into public.app_users(email,last_login_at) values($1,now())
    on conflict(email) do update set last_login_at=now(), updated_at=now()`, [email]);
}

async function loadNewDepo() {
  const p = db(); if (!p) return { value: null, meaningful: false };
  const ar = await p.query(`select * from public.new_depo_assets where is_active=true order by sort_order, name`);
  if (!ar.rows.length) return { value: null, meaningful: false };
  const pr = await p.query(`select * from public.new_depo_periods order by report_year, report_month`);
  const rr = await p.query(`select r.* from public.new_depo_rows r join public.new_depo_periods p on p.id=r.period_id order by p.report_year,p.report_month,r.row_order`);
  const periodRows = new Map();
  for (const r of rr.rows) {
    if (!periodRows.has(r.period_id)) periodRows.set(r.period_id, []);
    periodRows.get(r.period_id).push({ name:r.name||'', ndp:Number(r.ndp)||0, nominal:Number(r.nominal)||0, target:Number(r.target_ndp)||0 });
  }
  const periodsByAsset = new Map();
  for (const pRow of pr.rows) {
    if (!periodsByAsset.has(pRow.asset_id)) periodsByAsset.set(pRow.asset_id, {});
    const key = `${pRow.report_year}-${String(pRow.report_month).padStart(2,'0')}`;
    periodsByAsset.get(pRow.asset_id)[key] = {
      reportDate: pRow.report_date ? String(pRow.report_date).slice(0,10) : '',
      defaultTarget: Number(pRow.default_target)||100,
      workdayMode: pRow.workday_mode||'auto',
      manualWorkdays: Number(pRow.manual_workdays)||0,
      includeReportDate: !!pRow.include_report_date,
      rows: periodRows.get(pRow.id) || []
    };
  }
  const assets = ar.rows.map((a, i) => ({
    id:a.id,
    name:a.name,
    reportTitle:a.report_title,
    colors:{title:a.color_title,asset:a.color_asset,header:a.color_header,highlight:a.color_highlight,accent:a.color_accent},
    columns:a.columns || {},
    periods:periodsByAsset.get(a.id) || {}
  }));
  const now = new Date();
  const value = {version:2,activeAssetId:assets[0].id,ui:{month:now.getMonth(),year:now.getFullYear()},assets};
  return { value: JSON.stringify(value), meaningful: true };
}

async function syncNewDepo(value) {
  const s = safeParse(value, null);
  if (!s || !Array.isArray(s.assets)) throw new Error('DATA_NEW_DEPO_INVALID');
  await withTx(async c => {
    await q(c, 'delete from public.new_depo_rows');
    await q(c, 'delete from public.new_depo_periods');
    await q(c, 'delete from public.new_depo_assets');
    for (let ai=0; ai<s.assets.length; ai++) {
      const a=s.assets[ai]||{};
      const aid=isUuid(a.id)?a.id:crypto.randomUUID();
      const colors=a.colors||{}, cols=a.columns||{};
      await q(c, `insert into public.new_depo_assets
        (id,name,report_title,color_title,color_asset,color_header,color_highlight,color_accent,columns,sort_order,is_active)
        values($1,$2,$3,$4,$5,$6,$7,$8,$9::jsonb,$10,true)`, [
          aid, upper(a.name||`ASET ${ai+1}`), a.reportTitle||'REPORT NEW DEPO',
          colors.title||'#dff1d6', colors.asset||'#c9eaf7', colors.header||'#dceef9', colors.highlight||'#fff500', colors.accent||'#1677ff',
          JSON.stringify(cols), ai
        ]);
      for (const [key,pd] of Object.entries(a.periods||{})) {
        const m=String(key).match(/^(\d{4})-(\d{2})$/); if(!m) continue;
        const pid=crypto.randomUUID();
        await q(c, `insert into public.new_depo_periods
          (id,asset_id,report_year,report_month,report_date,default_target,workday_mode,manual_workdays,include_report_date)
          values($1,$2,$3,$4,$5,$6,$7,$8,$9)`, [pid,aid,Number(m[1]),Number(m[2]),pd.reportDate||null,Number(pd.defaultTarget)||100,pd.workdayMode==='manual'?'manual':'auto',Math.max(0,Number(pd.manualWorkdays)||0),!!pd.includeReportDate]);
        let ri=0;
        for (const row of (pd.rows||[])) {
          ri++;
          await q(c, `insert into public.new_depo_rows(period_id,row_order,name,ndp,nominal,target_ndp) values($1,$2,$3,$4,$5,$6)`, [pid,ri,upper(row.name||''),Math.max(0,Number(row.ndp)||0),Math.max(0,Math.round(Number(row.nominal)||0)),Math.max(0,Number(row.target)||0)]);
        }
      }
    }
  });
}

const DAILY_DEFAULT_COLUMNS={no:'Nomor',date:'Tanggal',tele:'Nama Tele',member:'ID Member',category:'Kategori',nominal:'Nominal',note:'Keterangan'};
const ANNUL_DEFAULT_COLUMNS={no:'Nomor',name:'Nama',member:'User ID',note:'Keterangan'};
const RESULT_DEFAULT_COLUMNS={no:'Nomor',category:'Nama Aset / Kategori',total:'Total Bersih'};
async function getSetting(type) {
  const p=db(); if(!p) return null;
  const r=await p.query('select * from public.report_settings where report_type=$1',[type]);
  return r.rows[0]||null;
}
async function loadDaily() {
  const p=db(); if(!p) return {value:null,meaningful:false};
  const [setR, assetsR, entriesR] = await Promise.all([
    getSetting('DAILY_ASSET'),
    p.query('select * from public.daily_assets where is_active=true order by sort_order,name'),
    p.query(`select d.*,a.name as asset_name from public.daily_report_entries d join public.daily_assets a on a.id=d.asset_id order by d.report_date,d.row_order`)
  ]);
  const setting=setR||{title:'REPORT HARIAN ASET',menu_name:'REPORT HARIAN ASET',columns:DAILY_DEFAULT_COLUMNS};
  const days={};
  for(const r of entriesR.rows){
    const date=String(r.report_date).slice(0,10); if(!days[date]) days[date]=[];
    days[date].push({id:r.id,tele:r.tele_name||'',member:r.member_id||'',category:r.asset_name||'UMUM',nominal:Number(r.nominal)||0,note:r.note||''});
  }
  const categories=assetsR.rows.map(r=>r.name);
  const obj={title:setting.title||'REPORT HARIAN ASET',menuName:setting.menu_name||'REPORT HARIAN ASET',categories:categories.length?categories:['UMUM'],columns:{...DAILY_DEFAULT_COLUMNS,...(setting.columns||{})},days};
  const meaningful=entriesR.rows.length>0 || categories.some(x=>x!=='UMUM') || !deepEqual(obj.columns,DAILY_DEFAULT_COLUMNS) || obj.title!=='REPORT HARIAN ASET' || obj.menuName!=='REPORT HARIAN ASET';
  return {value:JSON.stringify(obj),meaningful};
}
async function syncDaily(value,email) {
  const s=safeParse(value,null); if(!s||typeof s!=='object') throw new Error('DATA_DAILY_INVALID');
  await withTx(async c=>{
    await q(c, `insert into public.report_settings(report_type,title,menu_name,columns) values('DAILY_ASSET',$1,$2,$3::jsonb)
      on conflict(report_type) do update set title=excluded.title,menu_name=excluded.menu_name,columns=excluded.columns,updated_at=now()`, [s.title||'REPORT HARIAN ASET',s.menuName||s.title||'REPORT HARIAN ASET',JSON.stringify({...DAILY_DEFAULT_COLUMNS,...(s.columns||{})})]);
    await q(c,'delete from public.daily_report_entries');
    await q(c,'delete from public.daily_assets');
    const names=[]; const seen=new Set();
    for(const x of (Array.isArray(s.categories)?s.categories:[])){const n=upper(x); if(n&&!seen.has(n)){seen.add(n);names.push(n)}}
    for(const rows of Object.values(s.days||{})){for(const row of (rows||[])){const n=upper(row.category||'UMUM');if(n&&!seen.has(n)){seen.add(n);names.push(n)}}}
    if(!names.length) names.push('UMUM');
    const assetIds=new Map();
    for(let i=0;i<names.length;i++){const id=crypto.randomUUID();assetIds.set(names[i],id);await q(c,'insert into public.daily_assets(id,name,sort_order,is_active) values($1,$2,$3,true)',[id,names[i],i]);}
    for(const [date,rows] of Object.entries(s.days||{})){
      let order=0;
      for(const row of (rows||[])){order++;const cat=upper(row.category||names[0]||'UMUM');const aid=assetIds.get(cat)||assetIds.get(names[0]);await q(c,`insert into public.daily_report_entries(report_date,asset_id,row_order,tele_name,member_id,nominal,note,created_by_email) values($1,$2,$3,$4,$5,$6,$7,$8)`,[date,aid,order,upper(row.tele||''),upper(row.member||''),Math.max(0,Math.round(Number(row.nominal)||0)),upper(row.note||''),email]);}
    }
  });
}
async function loadAnnul() {
  const p=db(); if(!p) return {value:null,meaningful:false};
  const [setting, rowsR]=await Promise.all([getSetting('ANNUL'),p.query('select * from public.annul_entries order by report_date,row_order')]);
  const set=setting||{title:'ANULIR HARIAN',menu_name:'ANULIR HARIAN',columns:ANNUL_DEFAULT_COLUMNS}; const days={};
  for(const r of rowsR.rows){const date=String(r.report_date).slice(0,10);if(!days[date])days[date]=[];days[date].push({id:r.id,name:r.name||'',member:r.member_id||'',note:r.note||'ANULIR'});}
  const obj={title:set.title||'ANULIR HARIAN',menuName:set.menu_name||'ANULIR HARIAN',columns:{...ANNUL_DEFAULT_COLUMNS,...(set.columns||{})},days};
  const meaningful=rowsR.rows.length>0 || !deepEqual(obj.columns,ANNUL_DEFAULT_COLUMNS) || obj.title!=='ANULIR HARIAN' || obj.menuName!=='ANULIR HARIAN';
  return {value:JSON.stringify(obj),meaningful};
}
async function syncAnnul(value,email) {
  const s=safeParse(value,null); if(!s||typeof s!=='object') throw new Error('DATA_ANNUL_INVALID');
  await withTx(async c=>{
    await q(c,`insert into public.report_settings(report_type,title,menu_name,columns) values('ANNUL',$1,$2,$3::jsonb)
      on conflict(report_type) do update set title=excluded.title,menu_name=excluded.menu_name,columns=excluded.columns,updated_at=now()`,[s.title||'ANULIR HARIAN',s.menuName||s.title||'ANULIR HARIAN',JSON.stringify({...ANNUL_DEFAULT_COLUMNS,...(s.columns||{})})]);
    await q(c,'delete from public.annul_entries');
    for(const [date,rows] of Object.entries(s.days||{})){let order=0;for(const row of (rows||[])){order++;await q(c,'insert into public.annul_entries(report_date,row_order,name,member_id,note,created_by_email) values($1,$2,$3,$4,$5,$6)',[date,order,upper(row.name||''),upper(row.member||''),upper(row.note||'ANULIR'),email]);}}
  });
}
async function loadResults() {
  const setting=await getSetting('RESULT');
  const set=setting||{title:'HASIL REPORT HARIAN',menu_name:'HASIL REPORT HARIAN',columns:RESULT_DEFAULT_COLUMNS};
  const obj={title:set.title||'HASIL REPORT HARIAN',menuName:set.menu_name||'HASIL REPORT HARIAN',columns:{...RESULT_DEFAULT_COLUMNS,...(set.columns||{})}};
  const meaningful=!deepEqual(obj.columns,RESULT_DEFAULT_COLUMNS)||obj.title!=='HASIL REPORT HARIAN'||obj.menuName!=='HASIL REPORT HARIAN';
  return {value:JSON.stringify(obj),meaningful};
}
async function syncResults(value) {
  const s=safeParse(value,null);if(!s||typeof s!=='object')throw new Error('DATA_RESULTS_INVALID');
  const p=db();if(!p)throw new Error('DATABASE_NOT_CONFIGURED');
  await p.query(`insert into public.report_settings(report_type,title,menu_name,columns) values('RESULT',$1,$2,$3::jsonb)
    on conflict(report_type) do update set title=excluded.title,menu_name=excluded.menu_name,columns=excluded.columns,updated_at=now()`,[s.title||'HASIL REPORT HARIAN',s.menuName||s.title||'HASIL REPORT HARIAN',JSON.stringify({...RESULT_DEFAULT_COLUMNS,...(s.columns||{})})]);
}
async function loadCloudSnapshot() {
  if(!db()) return {connected:false, keys:{}};
  const [a,b,c,d]=await Promise.all([loadNewDepo(),loadDaily(),loadAnnul(),loadResults()]);
  return {connected:true,keys:{[TRACKED_KEYS[0]]:a,[TRACKED_KEYS[1]]:b,[TRACKED_KEYS[2]]:c,[TRACKED_KEYS[3]]:d}};
}
async function syncKey(key,value,email) {
  if(!TRACKED_KEYS.includes(key)) return;
  if(key===TRACKED_KEYS[0]) return syncNewDepo(value);
  if(key===TRACKED_KEYS[1]) return syncDaily(value,email);
  if(key===TRACKED_KEYS[2]) return syncAnnul(value,email);
  if(key===TRACKED_KEYS[3]) return syncResults(value);
}

function cloudBootstrapScript(snapshot) {
  const safe = JSON.stringify(snapshot).replace(/</g,'\\u003c').replace(/>/g,'\\u003e').replace(/&/g,'\\u0026').replace(/\u2028/g,'\\u2028').replace(/\u2029/g,'\\u2029');
  return `<script>
(()=>{
  const CLOUD=${safe};
  const TRACKED=${JSON.stringify(TRACKED_KEYS)};
  const nativeSet=Storage.prototype.setItem;
  const pending=new Map();
  const timers=new Map();
  let booting=true;
  const status=(text,kind='ok')=>{window.__cmlCloudStatus={text,kind};const paint=()=>{let el=document.getElementById('cloudSyncStatus');if(!el){const box=document.querySelector('.account-box');if(box){el=document.createElement('div');el.id='cloudSyncStatus';el.style.cssText='font-size:10px;font-weight:800;margin:8px 0;padding:6px 8px;border-radius:7px;background:#14253a;color:#bfe0ff;border:1px solid #294567';const logout=box.querySelector('.logout-btn');box.insertBefore(el,logout||null)}}if(el){el.textContent=text;el.style.color=kind==='err'?'#ffc9c9':kind==='busy'?'#ffe7a8':'#bfe0ff'}};if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',paint,{once:true});else paint()};
  async function push(key,value){if(!CLOUD.connected)return;status('☁ Menyimpan ke cloud…','busy');try{const r=await fetch('/api/data/sync',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({key,value}),credentials:'same-origin',keepalive:true});if(!r.ok)throw new Error((await r.json().catch(()=>({}))).error||'Sync gagal');status('☁ Cloud tersimpan','ok')}catch(e){console.error('Cloud sync:',e);status('⚠ Cloud gagal menyimpan','err')}}
  function schedule(key,value){pending.set(key,value);clearTimeout(timers.get(key));timers.set(key,setTimeout(()=>{pending.delete(key);push(key,value)},650))}
  const migrate=[];
  for(const key of TRACKED){const rec=CLOUD.keys?.[key];const local=localStorage.getItem(key);if(rec?.meaningful&&typeof rec.value==='string'){nativeSet.call(localStorage,key,rec.value)}else if(local){migrate.push([key,local])}else if(typeof rec?.value==='string'){nativeSet.call(localStorage,key,rec.value)}}
  Storage.prototype.setItem=function(key,value){nativeSet.call(this,key,value);if(this===localStorage&&!booting&&TRACKED.includes(String(key)))schedule(String(key),String(value))};
  booting=false;
  setTimeout(()=>{for(const [k,v] of migrate)schedule(k,v)},1200);
  window.addEventListener('pagehide',()=>{for(const key of TRACKED){const v=localStorage.getItem(key);if(v)fetch('/api/data/sync',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({key,value:v}),credentials:'same-origin',keepalive:true}).catch(()=>{})}});
  status(CLOUD.connected?'☁ Cloud tersambung':'⚠ Database belum tersambung',CLOUD.connected?'ok':'err');
})();
</script>`;
}

module.exports = async function handler(req, res) {
  const route = routeFromReq(req);
  const method = String(req.method || 'GET').toUpperCase();
  const session = getSession(req);

  if (route === 'login' && method === 'GET') {
    if (session) return redirect(res, '/');
    return serveHtml(res, LOGIN_HTML);
  }

  if ((route === 'app' || route === 'index.html') && method === 'GET') {
    if (!session) return redirect(res, '/login');
    let snapshot={connected:false,keys:{}};
    try { snapshot=await loadCloudSnapshot(); } catch(e){ console.error('Cloud bootstrap gagal:',e.message); }
    const html=fs.readFileSync(APP_HTML,'utf8').replace('<!--CLOUD_BOOTSTRAP-->',cloudBootstrapScript(snapshot));
    return serveHtmlText(res,html);
  }

  if (route === 'api/auth/session' && method === 'GET') {
    return sendJson(res, 200, { authenticated: !!session, user: session ? { email: session.email } : null, database: !!db() });
  }
  if (route === 'api/auth/logout' && method === 'POST') {
    return sendJson(res, 200, { ok: true }, [cookie(SESSION_COOKIE, '', { maxAge: 0 }),cookie(OTP_COOKIE, '', { maxAge: 0 })]);
  }
  if (route === 'api/auth/request-otp' && method === 'POST') {
    if (!ensureConfig(res)) return;
    const body = bodyOf(req); const email = normalizeEmail(body.email);
    if (!emailRe.test(email)) return sendJson(res, 400, { error: 'Format email tidak valid.' });
    const cookies = parseCookies(req); const prior = verifySignedPayload(cookies[OTP_COOKIE], SESSION_SECRET); const now = Date.now();
    if (prior && prior.type === 'otp' && prior.email === email && now < Number(prior.nextSendAt || 0)) {
      const seconds = Math.ceil((Number(prior.nextSendAt) - now) / 1000); return sendJson(res, 429, { error: `Tunggu ${seconds} detik sebelum meminta OTP baru.` });
    }
    const otp = String(crypto.randomInt(0, 1000000)).padStart(6, '0');
    const otpPayload = {type:'otp',email,hash:otpHash(email,otp),attempts:0,exp:now+OTP_TTL_MS,nextSendAt:now+RESEND_DELAY_MS};
    const otpToken = signPayload(otpPayload, SESSION_SECRET);
    const transporter = nodemailer.createTransport({service:'gmail',auth:{user:SMTP_USER,pass:SMTP_PASS}});
    try {
      await transporter.sendMail({from:`DAILY REPORT <${SMTP_USER}>`,to:email,subject:'Kode OTP Daily Report',text:`Kode OTP Anda: ${otp}\n\nKode berlaku 10 menit. Jangan berikan kode ini kepada orang lain.`,html:`<div style="font-family:Arial,sans-serif;max-width:520px;margin:auto"><h2>DAILY REPORT</h2><p>Gunakan kode OTP berikut untuk masuk:</p><div style="font-size:32px;font-weight:800;letter-spacing:8px;padding:16px;background:#f2f6fa;border-radius:10px;text-align:center">${otp}</div><p>Kode berlaku selama 10 menit.</p><p style="color:#667085;font-size:12px">Jangan berikan kode ini kepada siapa pun.</p></div>`});
      return sendJson(res,200,{message:`OTP telah dikirim ke ${email}.`},[cookie(OTP_COOKIE,otpToken,{maxAge:Math.ceil(OTP_TTL_MS/1000)})]);
    } catch(err){console.error('Gagal kirim OTP:',err?.message||err);return sendJson(res,500,{error:'OTP gagal dikirim. Periksa App Password Gmail dan konfigurasi SMTP.'});}
  }
  if (route === 'api/auth/verify-otp' && method === 'POST') {
    if (!ensureConfig(res)) return;
    const body=bodyOf(req);const email=normalizeEmail(body.email);const otp=String(body.otp||'').replace(/\D/g,'');
    if(!emailRe.test(email)||otp.length!==6)return sendJson(res,400,{error:'Email atau OTP tidak valid.'});
    const cookies=parseCookies(req);const rec=verifySignedPayload(cookies[OTP_COOKIE],SESSION_SECRET);
    if(!rec||rec.type!=='otp'||rec.email!==email)return sendJson(res,400,{error:'OTP tidak ditemukan. Silakan minta kode baru.'});
    const now=Date.now();if(now>Number(rec.exp||0))return sendJson(res,400,{error:'OTP sudah kedaluwarsa. Silakan minta kode baru.'},[cookie(OTP_COOKIE,'',{maxAge:0})]);
    const attempts=Number(rec.attempts||0)+1;if(attempts>5)return sendJson(res,429,{error:'Terlalu banyak percobaan. Silakan minta OTP baru.'},[cookie(OTP_COOKIE,'',{maxAge:0})]);
    if(!safeEqualString(rec.hash,otpHash(email,otp))){const nextRec={...rec,attempts};const remainingSec=Math.max(1,Math.ceil((Number(rec.exp)-now)/1000));return sendJson(res,400,{error:`OTP salah. Sisa percobaan: ${5-attempts}.`},[cookie(OTP_COOKIE,signPayload(nextRec,SESSION_SECRET),{maxAge:remainingSec})]);}
    const sessionPayload={type:'session',email,iat:now,exp:now+SESSION_TTL_MS};const sessionToken=signPayload(sessionPayload,SESSION_SECRET);
    try{await upsertLoginUser(email)}catch(e){console.error('Catat user gagal:',e.message)}
    return sendJson(res,200,{ok:true,user:{email}},[cookie(SESSION_COOKIE,sessionToken,{maxAge:Math.ceil(SESSION_TTL_MS/1000)}),cookie(OTP_COOKIE,'',{maxAge:0})]);
  }

  if (route === 'api/data/bootstrap' && method === 'GET') {
    if(!session)return sendJson(res,401,{error:'Sesi login diperlukan.'});
    try{return sendJson(res,200,await loadCloudSnapshot())}catch(e){console.error(e);return sendJson(res,500,{error:'Gagal membaca database.'})}
  }
  if (route === 'api/data/sync' && method === 'POST') {
    if(!session)return sendJson(res,401,{error:'Sesi login diperlukan.'});
    if(!db())return sendJson(res,503,{error:'Database belum terhubung ke project Vercel.'});
    const body=bodyOf(req);const key=String(body.key||'');const value=String(body.value||'');
    if(!TRACKED_KEYS.includes(key))return sendJson(res,400,{error:'Jenis data tidak dikenal.'});
    if(value.length>8_000_000)return sendJson(res,413,{error:'Data terlalu besar untuk disinkronkan.'});
    try{await syncKey(key,value,session.email);return sendJson(res,200,{ok:true,key})}catch(e){console.error('Sync gagal',key,e);return sendJson(res,500,{error:'Gagal menyimpan ke database.',detail:process.env.NODE_ENV==='development'?e.message:undefined})}
  }

  if (route === 'health' && method === 'GET') {
    return sendJson(res, 200, { ok: true, app: 'daily-report', auth: 'email-otp', database: !!db() });
  }
  securityHeaders(res, false);res.statusCode=404;res.setHeader('Content-Type','text/plain; charset=utf-8');res.end('Not Found');
};

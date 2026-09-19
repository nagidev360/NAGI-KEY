import 'dotenv/config';
import express from 'express';
import helmet from 'helmet';
import cors from 'cors';
import rateLimit from 'express-rate-limit';
import cookieParser from 'cookie-parser';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import crypto from 'crypto';
import pg from 'pg';
import { z } from 'zod';

const { Pool } = pg;
const app = express();
const PORT = Number(process.env.PORT || 10000);
const pool = process.env.DATABASE_URL ? new Pool({ connectionString: process.env.DATABASE_URL, ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized:false } : false, max:10 }) : null;
const origins = (process.env.CORS_ORIGINS || '').split(',').map(s=>s.trim()).filter(Boolean);

app.set('trust proxy', 1);
app.use(helmet());
const allowedOrigins=(process.env.CORS_ORIGINS||'').split(',').map(s=>s.trim()).filter(Boolean);\napp.use(cors({ origin:(origin,cb)=>{ if(!origin || allowedOrigins.length===0 || allowedOrigins.includes(origin)) return cb(null,true); return cb(new Error('CORS origin denied')); }, credentials:true }));
app.use(express.json({limit:'1mb'}));
app.use(cookieParser());
app.use(express.static('public'));
app.get('/',(req,res)=>res.sendFile('index.html',{root:'public'}));

const publicLimiter=rateLimit({windowMs:15*60*1000,max:300,standardHeaders:true,legacyHeaders:false});
const authLimiter=rateLimit({windowMs:15*60*1000,max:10,standardHeaders:true,legacyHeaders:false});
app.use('/api/v1/license/', publicLimiter);

const schema = `
CREATE TABLE IF NOT EXISTS products(
 id BIGSERIAL PRIMARY KEY, product_code TEXT UNIQUE NOT NULL, product_name TEXT NOT NULL,
 description TEXT DEFAULT '', status TEXT NOT NULL DEFAULT 'ACTIVE', version TEXT DEFAULT '1.0.0',
 created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS license_keys(
 id BIGSERIAL PRIMARY KEY, key TEXT UNIQUE NOT NULL, product_id BIGINT REFERENCES products(id),
 product TEXT NOT NULL, plan TEXT NOT NULL DEFAULT 'CUSTOM', status TEXT NOT NULL DEFAULT 'ACTIVE',
 start_date TIMESTAMPTZ NOT NULL DEFAULT NOW(), expiry_date TIMESTAMPTZ NOT NULL,
 max_activations INTEGER NOT NULL DEFAULT 1 CHECK(max_activations>0), notes TEXT DEFAULT '',
 metadata JSONB NOT NULL DEFAULT '{}'::jsonb, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
 updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS activations(
 id BIGSERIAL PRIMARY KEY, license_id BIGINT NOT NULL REFERENCES license_keys(id) ON DELETE CASCADE,
 device_id TEXT NOT NULL, device_name TEXT DEFAULT '', ip_address INET, user_agent TEXT DEFAULT '',
 app_version TEXT DEFAULT '', os_version TEXT DEFAULT '', activated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
 last_verified_at TIMESTAMPTZ, status TEXT NOT NULL DEFAULT 'active', metadata JSONB NOT NULL DEFAULT '{}'::jsonb
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_active_license_device ON activations(license_id,device_id) WHERE status='active';
CREATE INDEX IF NOT EXISTS ix_license_product ON license_keys(product);
CREATE INDEX IF NOT EXISTS ix_license_status ON license_keys(status);
CREATE INDEX IF NOT EXISTS ix_activation_license ON activations(license_id);
CREATE TABLE IF NOT EXISTS admin_users(
 id BIGSERIAL PRIMARY KEY, email TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'SUPER_ADMIN',
 status TEXT NOT NULL DEFAULT 'ACTIVE', created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), last_login_at TIMESTAMPTZ
);
CREATE TABLE IF NOT EXISTS audit_logs(
 id BIGSERIAL PRIMARY KEY, action TEXT NOT NULL, license_id BIGINT REFERENCES license_keys(id) ON DELETE SET NULL,
 activation_id BIGINT REFERENCES activations(id) ON DELETE SET NULL, admin_id BIGINT REFERENCES admin_users(id) ON DELETE SET NULL,
 product_id BIGINT REFERENCES products(id) ON DELETE SET NULL, ip_address INET, metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
 created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS ix_audit_created ON audit_logs(created_at DESC);
`;

let dbReady=false;
async function initDb(){
 if(!pool) return;
 await pool.query(schema);
 await pool.query('INSERT INTO products(product_code,product_name,description) VALUES($1,$2,$3) ON CONFLICT(product_code) DO NOTHING',
 ['SANTHOSH_BARCODE_GEN','SANTHOSH BARCODE GEN','Licensed barcode and QR label generator']);
 if(process.env.ADMIN_EMAIL && process.env.ADMIN_PASSWORD){
  const hash=await bcrypt.hash(process.env.ADMIN_PASSWORD,12);
  await pool.query(`INSERT INTO admin_users(email,password_hash) VALUES($1,$2)
   ON CONFLICT(email) DO UPDATE SET password_hash=EXCLUDED.password_hash,updated_at=NOW(),status='ACTIVE'`,
   [process.env.ADMIN_EMAIL.toLowerCase(),hash]);
 }
 dbReady=true;
}
const now=()=>new Date();
const clientIp=req=>req.ip?.replace(/^::ffff:/,'') || null;
function audit(req,action,{licenseId=null,activationId=null,adminId=null,productId=null,metadata={}}={}){
 return pool.query('INSERT INTO audit_logs(action,license_id,activation_id,admin_id,product_id,ip_address,metadata) VALUES($1,$2,$3,$4,$5,$6,$7)',
 [action,licenseId,activationId,adminId,productId,clientIp(req),metadata]).catch(()=>{});
}
function makeKey(){const b=n=>crypto.randomBytes(n).toString('hex').toUpperCase(); return `NAGI-${b(2)}-${b(2)}-${b(2)}-${b(2)}`;}
function signSession(user){return jwt.sign({sub:String(user.id),email:user.email,role:user.role},process.env.JWT_SECRET,{expiresIn:'8h'});}
function admin(req,res,next){
 try{
  const token=req.cookies.nagi_admin || (req.headers.authorization||'').replace(/^Bearer\s+/,'');
  if(!token) return res.status(401).json({success:false,error:{code:'UNAUTHORIZED',message:'Authentication required.'}});
  req.admin=jwt.verify(token,process.env.JWT_SECRET);
  next();
 }catch{return res.status(401).json({success:false,error:{code:'UNAUTHORIZED',message:'Session expired or invalid.'}})}
}
function safeError(res,e){ console.error(e); return res.status(500).json({success:false,error:{code:'SERVER_ERROR',message:'A server error occurred.'}}); }

app.get(['/health','/api/health'],async(req,res)=>{
 if(!pool) return res.status(503).json({ok:false,service:'NAGI KEY',database:'disconnected'});
 try{await pool.query('SELECT 1'); return res.json({ok:true,service:'NAGI KEY',database:'connected'});}
 catch{return res.status(503).json({ok:false,service:'NAGI KEY',database:'disconnected'});}
});

app.post('/api/v1/admin/login',authLimiter,async(req,res)=>{
 if(!pool || !process.env.JWT_SECRET) return res.status(503).json({success:false,error:{code:'SERVER_UNAVAILABLE',message:'Authentication service unavailable.'}});
 try{
  const {email,password}=z.object({email:z.string().email(),password:z.string().min(1)}).parse(req.body);
  const r=await pool.query('SELECT * FROM admin_users WHERE email=$1 AND status=\'ACTIVE\'', [email.toLowerCase()]);
  if(!r.rowCount || !(await bcrypt.compare(password,r.rows[0].password_hash))){ await audit(req,'FAILED_LOGIN',{}); return res.status(401).json({success:false,error:{code:'INVALID_CREDENTIALS',message:'Invalid credentials.'}});}
  const u=r.rows[0]; await pool.query('UPDATE admin_users SET last_login_at=NOW() WHERE id=$1',[u.id]); await audit(req,'LOGIN',{adminId:u.id});
  res.cookie('nagi_admin',signSession(u),{httpOnly:true,secure:process.env.NODE_ENV==='production',sameSite:'lax',maxAge:8*60*60*1000});
  return res.json({success:true,data:{email:u.email,role:u.role}});
 }catch(e){return e?.name==='ZodError'?res.status(400).json({success:false,error:{code:'VALIDATION_ERROR',message:'Invalid login data.'}}):safeError(res,e);}
});
app.post('/api/v1/admin/logout',admin,async(req,res)=>{res.clearCookie('nagi_admin'); await audit(req,'LOGOUT',{adminId:req.admin.sub}); res.json({success:true,data:{}});});

app.get('/api/v1/admin/licenses',admin,async(req,res)=>{
 try{
  const q=z.object({search:z.string().optional(),status:z.string().optional(),product:z.string().optional()}).parse(req.query);
  const where=[]; const args=[]; let i=1;
  if(q.search){where.push(`(l.key ILIKE $${i} OR l.notes ILIKE $${i})`);args.push('%'+q.search+'%');i++;}
  if(q.status){where.push(`l.status=$${i++}`);args.push(q.status);}
  if(q.product){where.push(`l.product=$${i++}`);args.push(q.product);}
  const r=await pool.query(`SELECT l.id,l.key,l.product,l.plan,l.status,l.start_date,l.expiry_date,l.max_activations,l.notes,l.created_at,
    (SELECT count(*) FROM activations a WHERE a.license_id=l.id AND a.status='active')::int active_activations
    FROM license_keys l ${where.length?'WHERE '+where.join(' AND '):''} ORDER BY l.created_at DESC LIMIT 500`,args);
  res.json({success:true,data:r.rows});
 }catch(e){return safeError(res,e);}
});
app.get('/api/v1/admin/licenses/:id',admin,async(req,res)=>{try{const r=await pool.query('SELECT * FROM license_keys WHERE id=$1',[req.params.id]);if(!r.rowCount)return res.status(404).json({success:false,error:{code:'NOT_FOUND',message:'License not found.'}});res.json({success:true,data:r.rows[0]});}catch(e){safeError(res,e);}});
app.post('/api/v1/admin/licenses',admin,async(req,res)=>{
 try{
  const body=z.object({product:z.string().min(1).max(100),plan:z.string().default('CUSTOM'),expiry_date:z.coerce.date(),max_activations:z.coerce.number().int().positive().max(10000),notes:z.string().max(2000).optional(),metadata:z.record(z.string(),z.any()).optional()}).parse(req.body);
  const product=await pool.query('SELECT id FROM products WHERE product_code=$1',[body.product]); if(!product.rowCount)return res.status(400).json({success:false,error:{code:'PRODUCT_NOT_FOUND',message:'Product is not registered.'}});
  const key=makeKey(); const r=await pool.query(`INSERT INTO license_keys(key,product_id,product,plan,expiry_date,max_activations,notes,metadata) VALUES($1,$2,$3,$4,$5,$6,$7,$8) RETURNING id,key,product,plan,status,start_date,expiry_date,max_activations,notes`,[key,product.rows[0].id,body.product,body.plan,body.expiry_date,body.max_activations,body.notes||'',body.metadata||{}]);
  await audit(req,'LICENSE_CREATED',{licenseId:r.rows[0].id,adminId:req.admin.sub,productId:product.rows[0].id}); res.status(201).json({success:true,data:r.rows[0]});
 }catch(e){return e?.name==='ZodError'?res.status(400).json({success:false,error:{code:'VALIDATION_ERROR',message:'Invalid license data.'}}):safeError(res,e);}
});
async function setLicenseStatus(req,res,status,action){try{const r=await pool.query('UPDATE license_keys SET status=$1,updated_at=NOW() WHERE id=$2 RETURNING id,status',[status,req.params.id]);if(!r.rowCount)return res.status(404).json({success:false,error:{code:'NOT_FOUND',message:'License not found.'}});await audit(req,action,{licenseId:req.params.id,adminId:req.admin.sub});res.json({success:true,data:r.rows[0]});}catch(e){safeError(res,e);}}
app.post('/api/v1/admin/licenses/:id/revoke',admin,(req,res)=>setLicenseStatus(req,res,'REVOKED','LICENSE_REVOKED'));
app.post('/api/v1/admin/licenses/:id/suspend',admin,(req,res)=>setLicenseStatus(req,res,'SUSPENDED','LICENSE_SUSPENDED'));
app.post('/api/v1/admin/licenses/:id/reactivate',admin,(req,res)=>setLicenseStatus(req,res,'ACTIVE','LICENSE_REACTIVATED'));
app.post('/api/v1/admin/licenses/:id/extend',admin,async(req,res)=>{try{const {expiry_date}=z.object({expiry_date:z.coerce.date()}).parse(req.body);const r=await pool.query('UPDATE license_keys SET expiry_date=$1,updated_at=NOW() WHERE id=$2 RETURNING id,expiry_date',[expiry_date,req.params.id]);if(!r.rowCount)return res.status(404).json({success:false,error:{code:'NOT_FOUND',message:'License not found.'}});await audit(req,'LICENSE_EXTENDED',{licenseId:req.params.id,adminId:req.admin.sub});res.json({success:true,data:r.rows[0]});}catch(e){safeError(res,e);}});
app.get('/api/v1/admin/licenses/:id/activations',admin,async(req,res)=>{try{const r=await pool.query('SELECT id,license_id,device_id,device_name,app_version,os_version,activated_at,last_verified_at,status FROM activations WHERE license_id=$1 ORDER BY activated_at DESC',[req.params.id]);res.json({success:true,data:r.rows});}catch(e){safeError(res,e);}});
app.post('/api/v1/admin/activations/:id/deactivate',admin,async(req,res)=>{try{const r=await pool.query("UPDATE activations SET status='inactive' WHERE id=$1 RETURNING id,status,license_id",[req.params.id]);if(!r.rowCount)return res.status(404).json({success:false,error:{code:'NOT_FOUND',message:'Activation not found.'}});await audit(req,'DEVICE_DEACTIVATED',{activationId:req.params.id,licenseId:r.rows[0].license_id,adminId:req.admin.sub});res.json({success:true,data:r.rows[0]});}catch(e){safeError(res,e);}});

const licenseInput=z.object({key:z.string().min(10),product:z.string().min(1),device_id:z.string().min(6).max(300),device_name:z.string().max(200).optional(),app_version:z.string().max(50).optional(),os_version:z.string().max(100).optional()});
app.post('/api/v1/license/activate',async(req,res)=>{
 try{
  const b=licenseInput.parse(req.body); const c=await pool.connect();
  try{
   await c.query('BEGIN'); const l=await c.query('SELECT * FROM license_keys WHERE key=$1 FOR UPDATE',[b.key]);
   if(!l.rowCount){await c.query('ROLLBACK');return res.status(404).json({success:false,status:'INVALID',error:{code:'INVALID_LICENSE',message:'License key is invalid.'}});}
   const lic=l.rows[0], today=now();
   if(lic.product!==b.product){await c.query('ROLLBACK');return res.status(400).json({success:false,status:'PRODUCT_MISMATCH',error:{code:'PRODUCT_MISMATCH',message:'License does not belong to this product.'}});}
   if(lic.status==='REVOKED'){await c.query('ROLLBACK');return res.status(403).json({success:false,status:'REVOKED',error:{code:'LICENSE_REVOKED',message:'License has been revoked.'}});}
   if(lic.status==='SUSPENDED'){await c.query('ROLLBACK');return res.status(403).json({success:false,status:'SUSPENDED',error:{code:'LICENSE_SUSPENDED',message:'License is suspended.'}});}
   if(new Date(lic.start_date)>today || new Date(lic.expiry_date)<today){await c.query('ROLLBACK');return res.status(403).json({success:false,status:'EXPIRED',error:{code:'LICENSE_EXPIRED',message:'License is outside its active period.'}});}
   const existing=await c.query("SELECT * FROM activations WHERE license_id=$1 AND device_id=$2 AND status='active'",[lic.id,b.device_id]);
   let a=existing.rows[0];
   if(!a){
    const count=await c.query("SELECT count(*)::int n FROM activations WHERE license_id=$1 AND status='active'",[lic.id]);
    if(count.rows[0].n>=lic.max_activations){await c.query('ROLLBACK');return res.status(409).json({success:false,status:'DEVICE_NOT_AUTHORIZED',error:{code:'ACTIVATION_LIMIT_REACHED',message:'Activation limit reached.'}});}
    const ins=await c.query("INSERT INTO activations(license_id,device_id,device_name,ip_address,user_agent,app_version,os_version,last_verified_at) VALUES($1,$2,$3,$4,$5,$6,$7,NOW()) RETURNING *",[lic.id,b.device_id,b.device_name||'',clientIp(req),req.get('user-agent')||'',b.app_version||'',b.os_version||'']); a=ins.rows[0];
   }else await c.query("UPDATE activations SET last_verified_at=NOW(),device_name=COALESCE(NULLIF($1,''),device_name),app_version=COALESCE(NULLIF($2,''),app_version) WHERE id=$3",[b.device_name||'',b.app_version||'',a.id]);
   await c.query('COMMIT'); await audit(req,'LICENSE_ACTIVATED',{licenseId:lic.id,activationId:a.id,metadata:{product:b.product}});
   res.json({success:true,status:'active',license:{product:lic.product,plan:lic.plan,expiry_date:lic.expiry_date,device_id:b.device_id,activation_id:a.id}});
  }catch(e){await c.query('ROLLBACK').catch(()=>{});throw e;}finally{c.release();}
 }catch(e){return e?.name==='ZodError'?res.status(400).json({success:false,status:'INVALID',error:{code:'VALIDATION_ERROR',message:'Invalid activation data.'}}):safeError(res,e);}
});
app.post('/api/v1/license/verify',async(req,res)=>{
 try{
  const b=licenseInput.pick({key:true,product:true,device_id:true}).parse(req.body);
  const l=await pool.query('SELECT * FROM license_keys WHERE key=$1',[b.key]); if(!l.rowCount)return res.json({success:false,status:'INVALID'});
  const lic=l.rows[0]; if(lic.product!==b.product)return res.json({success:false,status:'PRODUCT_MISMATCH'});
  if(lic.status==='REVOKED')return res.json({success:false,status:'REVOKED'});
  if(lic.status==='SUSPENDED')return res.json({success:false,status:'SUSPENDED'});
  if(new Date(lic.start_date)>now() || new Date(lic.expiry_date)<now())return res.json({success:false,status:'EXPIRED'});
  const a=await pool.query("SELECT id FROM activations WHERE license_id=$1 AND device_id=$2 AND status='active'",[lic.id,b.device_id]); if(!a.rowCount)return res.json({success:false,status:'DEVICE_NOT_AUTHORIZED'});
  await pool.query('UPDATE activations SET last_verified_at=NOW() WHERE id=$1',[a.rows[0].id]); await audit(req,'LICENSE_VERIFIED',{licenseId:lic.id,activationId:a.rows[0].id});
  res.json({success:true,status:'ACTIVE',license:{product:lic.product,plan:lic.plan,expiry_date:lic.expiry_date,device_id:b.device_id,activation_id:a.rows[0].id}});
 }catch(e){return e?.name==='ZodError'?res.status(400).json({success:false,status:'INVALID'}):safeError(res,e);}
});
app.post('/api/v1/license/deactivate',async(req,res)=>{try{const b=licenseInput.pick({key:true,product:true,device_id:true}).parse(req.body);const r=await pool.query("UPDATE activations a SET status='inactive' FROM license_keys l WHERE a.license_id=l.id AND l.key=$1 AND l.product=$2 AND a.device_id=$3 AND a.status='active' RETURNING a.id,a.license_id",[b.key,b.product,b.device_id]);if(!r.rowCount)return res.status(404).json({success:false,error:{code:'ACTIVATION_NOT_FOUND',message:'Active activation not found.'}});await audit(req,'LICENSE_DEACTIVATED',{licenseId:r.rows[0].license_id,activationId:r.rows[0].id});res.json({success:true,data:{status:'inactive'}});}catch(e){safeError(res,e);}});

app.use((err,req,res,next)=>{ if(err.message==='CORS origin denied') return res.status(403).json({success:false,error:{code:'CORS_DENIED',message:'Origin not allowed.'}}); return res.status(500).json({success:false,error:{code:'SERVER_ERROR',message:'Request failed.'}}); });

async function start(){try{if(!pool)console.warn('DATABASE_URL is not configured.');else await initDb();app.listen(PORT,'0.0.0.0',()=>console.log(`NAGI KEY listening on ${PORT}`));}catch(e){console.error('Startup database error:',e.message);app.listen(PORT,'0.0.0.0',()=>console.log(`NAGI KEY listening on ${PORT} (database unavailable)`));}}
start();

import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import Database from 'better-sqlite3';
import midtransClient from 'midtrans-client';
import nodemailer from 'nodemailer';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();
const db = new Database(process.env.RAILWAY_ENVIRONMENT ? '/app/data/dalvora.db' : 'dalvora.db');
const PORT = process.env.PORT || 3000;
const SECRET = process.env.JWT_SECRET || 'dev-only-change-this-secret';

const MIDTRANS_SERVER_KEY = process.env.MIDTRANS_SERVER_KEY || '';
const MIDTRANS_CLIENT_KEY = process.env.MIDTRANS_CLIENT_KEY || '';
const MIDTRANS_IS_PRODUCTION = String(process.env.MIDTRANS_IS_PRODUCTION || 'false').toLowerCase() === 'true';

const snap = MIDTRANS_SERVER_KEY
  ? new midtransClient.Snap({
      isProduction: MIDTRANS_IS_PRODUCTION,
      serverKey: MIDTRANS_SERVER_KEY,
      clientKey: MIDTRANS_CLIENT_KEY
    })
  : null;

app.use(cors());
app.use(express.json({limit:'6mb'}));
app.use(express.static(path.join(__dirname, 'public')));

db.exec(`
CREATE TABLE IF NOT EXISTS users(
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 name TEXT NOT NULL,
 email TEXT UNIQUE NOT NULL,
 password TEXT NOT NULL,
 role TEXT NOT NULL DEFAULT 'customer',
 created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS products(
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 name TEXT NOT NULL,
 price INTEGER NOT NULL,
 description TEXT DEFAULT '',
 emoji TEXT DEFAULT '🥤',
 active INTEGER DEFAULT 1,
 stock INTEGER DEFAULT 999,
 image TEXT DEFAULT '',
 created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS orders(
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 order_no TEXT UNIQUE NOT NULL,
 user_id INTEGER,
 customer_name TEXT NOT NULL,
 phone TEXT NOT NULL,
 address TEXT NOT NULL,
 payment_method TEXT NOT NULL,
 payment_status TEXT NOT NULL DEFAULT 'pending',
 order_status TEXT NOT NULL DEFAULT 'new',
 total INTEGER NOT NULL,
 created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS order_items(
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 order_id INTEGER NOT NULL,
 product_id INTEGER NOT NULL,
 name TEXT NOT NULL,
 price INTEGER NOT NULL,
 qty INTEGER NOT NULL
);
`);


try { db.exec("ALTER TABLE products ADD COLUMN image TEXT DEFAULT ''"); } catch {}

const adminEmail = process.env.ADMIN_EMAIL || 'admin@dalvora.id';
const adminPass = process.env.ADMIN_PASSWORD || 'ganti-password-ini';
const exists = db.prepare('SELECT id FROM users WHERE email=?').get(adminEmail);
if (!exists) {
  db.prepare('INSERT INTO users(name,email,password,role) VALUES(?,?,?,?)')
    .run('DALVORA Admin', adminEmail, bcrypt.hashSync(adminPass, 10), 'admin');
}

const count = db.prepare('SELECT COUNT(*) c FROM products').get().c;
if (!count) {
  const add = db.prepare('INSERT INTO products(name,price,description,emoji) VALUES(?,?,?,?)');
  [
    ['Korean Lemonade',20000,'Segar dan dingin.','🍋'],
    ['Citrus Honey Tea',15000,'Citrus, madu & orange jam.','🍊'],
    ['Jasmine Green Tea',10000,'Harum dan menyegarkan.','🍵'],
    ['CoconutShake Vanilla',10000,'Creamy coconut vanilla.','🥥'],
    ['CoconutShake Coklat',10000,'Coconut shake cokelat.','🍫'],
    ['CoconutShake Strawberry',12000,'Creamy strawberry.','🍓'],
    ['CoconutShake Choco Chunk',15000,'Dengan choco chunk.','🍫'],
    ['CoconutShake Choco Fudge',15000,'Rich chocolate fudge.','🍫'],
    ['CoconutShake White Coffee',15000,'Coconut + white coffee.','☕'],
    ['Jeju Orange',15000,'Orange drink yang fresh.','🍊']
  ].forEach(p=>add.run(...p));
}

function token(user){ return jwt.sign({id:user.id,role:user.role,email:user.email},SECRET,{expiresIn:'7d'}); }
function auth(req,res,next){
  const h=req.headers.authorization||'';
  try{ req.user=jwt.verify(h.replace('Bearer ',''),SECRET); next(); }
  catch{ res.status(401).json({error:'Unauthorized'}); }
}
function admin(req,res,next){ if(req.user?.role!=='admin') return res.status(403).json({error:'Admin only'}); next(); }

app.get('/api/products',(req,res)=>res.json(db.prepare('SELECT * FROM products WHERE active=1 ORDER BY id DESC').all()));

app.post('/api/register',(req,res)=>{
  const {name,email,password}=req.body;
  if(!name||!email||!password||password.length<6) return res.status(400).json({error:'Data tidak lengkap atau password minimal 6 karakter'});
  try{
    const hash=bcrypt.hashSync(password,10);
    const r=db.prepare('INSERT INTO users(name,email,password) VALUES(?,?,?)').run(name,email.toLowerCase(),hash);
    const u=db.prepare('SELECT id,name,email,role FROM users WHERE id=?').get(r.lastInsertRowid);
    res.json({user:u,token:token(u)});
  }catch(e){res.status(409).json({error:'Email sudah digunakan'});}
});

app.post('/api/login',(req,res)=>{
  const {email,password}=req.body;
  const u=db.prepare('SELECT * FROM users WHERE email=?').get((email||'').toLowerCase());
  if(!u||!bcrypt.compareSync(password||'',u.password)) return res.status(401).json({error:'Email atau password salah'});
  const safe={id:u.id,name:u.name,email:u.email,role:u.role};
  res.json({user:safe,token:token(safe)});
});

app.post('/api/orders',auth,async(req,res)=>{
  const {name,phone,address,payment_method,items}=req.body;
  if(!name||!phone||!address||!Array.isArray(items)||!items.length)
    return res.status(400).json({error:'Data pesanan belum lengkap'});

  let total=0;
  const clean=[];

  for(const x of items){
    const p=db.prepare('SELECT * FROM products WHERE id=? AND active=1').get(x.product_id);
    const qty=Math.max(1,Math.min(99,Number(x.qty)||1));
    if(!p) return res.status(400).json({error:'Produk tidak ditemukan'});
    total+=p.price*qty;
    clean.push({p,qty});
  }

  const orderNo='DV'+Date.now().toString().slice(-8);

  const tx=db.transaction(()=>{
    const r=db.prepare(`
      INSERT INTO orders(
        order_no,user_id,customer_name,phone,address,payment_method,total
      ) VALUES(?,?,?,?,?,?,?)
    `).run(
      orderNo,
      req.user.id,
      name,
      phone,
      address,
      payment_method||'QRIS',
      total
    );

    const add=db.prepare(`
      INSERT INTO order_items(order_id,product_id,name,price,qty)
      VALUES(?,?,?,?,?)
    `);

    clean.forEach(x=>add.run(
      r.lastInsertRowid,
      x.p.id,
      x.p.name,
      x.p.price,
      x.qty
    ));

    return r.lastInsertRowid;
  });

  const id=tx();

  if((payment_method||'QRIS').toUpperCase()==='QRIS'){
    if(!snap){
      return res.status(500).json({
        error:'Midtrans belum dikonfigurasi di server'
      });
    }

    try{
      const base=MIDTRANS_IS_PRODUCTION
  ? 'https://api.midtrans.com'
  : 'https://api.sandbox.midtrans.com';

const auth=Buffer.from(MIDTRANS_SERVER_KEY+':').toString('base64');

const mr=await fetch(base+'/v2/charge',{
  method:'POST',
  headers:{
    Accept:'application/json',
    'Content-Type':'application/json',
    Authorization:'Basic '+auth
  },
  body:JSON.stringify({
    payment_type:'gopay',
    transaction_details:{
      order_id:orderNo,
      gross_amount:total
    },
    item_details:clean.map(x=>({
      id:String(x.p.id),
      price:x.p.price,
      quantity:x.qty,
      name:x.p.name
    })),
    customer_details:{
      first_name:name,
      email:req.user.email,
      phone
    },
    gopay:{
      enable_callback:false
    }
  })
});

const result=await mr.json();

if(!mr.ok){
  console.error('MIDTRANS CHARGE ERROR:',JSON.stringify(result));
  return res.status(mr.status).json({
    error:result.status_message||'Gagal membuat pembayaran GoPay'
  });
}

const qrAction=(result.actions||[]).find(
  x=>x.name==='generate-qr-code-v2'
) || (result.actions||[]).find(
  x=>x.name==='generate-qr-code'
);

const redirectAction=(result.actions||[]).find(
  x=>x.name==='deeplink-redirect'
);

if(!qrAction){
  console.error('MIDTRANS NO QR:',JSON.stringify(result));
  return res.status(502).json({
    error:'Midtrans tidak mengembalikan URL QR',
    transaction_status:result.transaction_status||null
  });
}

const qr_url=qrAction.url;
const redirect_url=redirectAction?.url||null;

console.log("MIDTRANS RESULT:", JSON.stringify({order_no:orderNo, qr_url:qr_url ? "[ADA]" : "[KOSONG]", redirect_url:redirect_url ? "[ADA]" : "[KOSONG]", payment_method:'gopay'}));

      return res.json({
        order_id:id,
        order_no:orderNo,
        total,
        payment:{
          status:'pending',
          provider:'midtrans',
          token:result.token,
          redirect_url:redirect_url, qr_url:qr_url
        }
      });
    }catch(e){
      console.error('Midtrans create transaction error:',e?.message||e);
      return res.status(502).json({
        error:'Gagal membuat pembayaran QRIS'
      });
    }
  }

  res.json({
    order_id:id,
    order_no:orderNo,
    total,
    payment:{
      status:'pending',
      provider:'manual',
      message:'Pesanan berhasil dibuat.'
    }
  });
});

app.get('/api/payment/config',(req,res)=>{
  res.json({
    clientKey:MIDTRANS_CLIENT_KEY,
    isProduction:MIDTRANS_IS_PRODUCTION
  });
});

app.get('/api/payment/qr/:orderNo',async(req,res)=>{
  try{
    if(!MIDTRANS_SERVER_KEY){
      return res.status(500).json({error:'Midtrans belum dikonfigurasi'});
    }

    const base=MIDTRANS_IS_PRODUCTION
      ? 'https://api.midtrans.com'
      : 'https://api.sandbox.midtrans.com';

    const auth=Buffer.from(MIDTRANS_SERVER_KEY+':').toString('base64');

    const r=await fetch(
      base+'/v2/'+encodeURIComponent(req.params.orderNo)+'/status',
      {
        headers:{
          Accept:'application/json',
          'Content-Type':'application/json',
          Authorization:'Basic '+auth
        }
      }
    );

    const data=await r.json();

    if(!r.ok){
      return res.status(r.status).json({
        error:data.status_message||'Gagal mengambil status Midtrans'
      });
    }

    const qrAction=(data.actions||[]).find(
      x=>x.name==='generate-qr-code-v2'
    ) || (data.actions||[]).find(
      x=>x.name==='generate-qr-code'
    );

    if(!qrAction){
      return res.status(404).json({
        error:'QR belum tersedia',
        transaction_status:data.transaction_status||null
      });
    }

    res.json({
      order_id:data.order_id,
      transaction_status:data.transaction_status,
      qr_url:qrAction.url
    });
  }catch(e){
    console.error('Midtrans QR error:',e?.message||e);
    res.status(500).json({error:'Gagal mengambil QR Midtrans'});
  }
});

app.get('/api/my-orders',auth,(req,res)=>{
  const orders=db.prepare('SELECT * FROM orders WHERE user_id=? ORDER BY id DESC').all(req.user.id);
  const items=db.prepare('SELECT * FROM order_items WHERE order_id=?');
  res.json(orders.map(o=>({...o,items:items.all(o.id)})));
});

app.post('/api/midtrans/notification',async(req,res)=>{
  try{
    if(!snap) return res.status(500).json({error:'Midtrans belum dikonfigurasi'});

    const statusResponse=await snap.transaction.notification(req.body);
    const orderNo=statusResponse.order_id;
    const transactionStatus=statusResponse.transaction_status;
    const fraudStatus=statusResponse.fraud_status;

    let paymentStatus='pending';

    if(
      transactionStatus==='settlement' ||
      (transactionStatus==='capture' && fraudStatus==='accept')
    ){
      paymentStatus='paid';
    }else if(
      transactionStatus==='expire' ||
      transactionStatus==='cancel' ||
      transactionStatus==='deny'
    ){
      paymentStatus='failed';
    }

    db.prepare(`
      UPDATE orders
      SET payment_status=?
      WHERE order_no=?
    `).run(paymentStatus,orderNo);

    res.json({ok:true});
  }catch(e){
    console.error('Midtrans notification error:',e?.message||e);
    res.status(500).json({error:'Notification gagal diproses'});
  }
});

app.get('/api/admin/orders',auth,admin,(req,res)=>{
  const orders=db.prepare('SELECT * FROM orders ORDER BY id DESC').all();
  const items=db.prepare('SELECT * FROM order_items WHERE order_id=?');
  res.json(orders.map(o=>({...o,items:items.all(o.id)})));
});

app.patch('/api/admin/orders/:id',auth,admin,(req,res)=>{
  const {order_status,payment_status}=req.body;
  db.prepare('UPDATE orders SET order_status=COALESCE(?,order_status), payment_status=COALESCE(?,payment_status) WHERE id=?')
    .run(order_status||null,payment_status||null,req.params.id);
  res.json({ok:true});
});

app.post('/api/admin/products',auth,admin,(req,res)=>{
  const {name,price,description,emoji,stock,image}=req.body;
  if(!name||Number(price)<=0) return res.status(400).json({error:'Nama dan harga wajib'});
  const r=db.prepare('INSERT INTO products(name,price,description,emoji,stock,image) VALUES(?,?,?,?,?,?)')
    .run(String(name).trim(),Number(price),description||'',emoji||'🥤',stock??999,image||'');
  res.json({id:r.lastInsertRowid});
});

app.patch('/api/admin/products/:id',auth,admin,(req,res)=>{
  const {name,price,description,emoji,stock,image,active}=req.body;
  const p=db.prepare('SELECT id FROM products WHERE id=?').get(req.params.id);
  if(!p) return res.status(404).json({error:'Produk tidak ditemukan'});
  db.prepare(`UPDATE products SET
    name=COALESCE(?,name), price=COALESCE(?,price), description=COALESCE(?,description),
    emoji=COALESCE(?,emoji), stock=COALESCE(?,stock), image=COALESCE(?,image),
    active=COALESCE(?,active) WHERE id=?`)
    .run(name??null, price!=null?Number(price):null, description??null, emoji??null,
         stock!=null?Number(stock):null, image??null, active!=null?Number(active):null, req.params.id);
  res.json({ok:true});
});

app.delete('/api/admin/products/:id',auth,admin,(req,res)=>{
  db.prepare('UPDATE products SET active=0 WHERE id=?').run(req.params.id); res.json({ok:true});
});

app.get('/api/admin/stats',auth,admin,(req,res)=>{
  const revenue=db.prepare("SELECT COALESCE(SUM(total),0) total FROM orders WHERE payment_status='paid'").get().total;
  const orders=db.prepare('SELECT COUNT(*) c FROM orders').get().c;
  const customers=db.prepare("SELECT COUNT(*) c FROM users WHERE role='customer'").get().c;
  res.json({revenue,orders,customers});
});

app.listen(PORT,()=>console.log(`DALVORA running on http://localhost:${PORT}`));


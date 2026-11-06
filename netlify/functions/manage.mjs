import { createHmac, timingSafeEqual } from 'node:crypto';
const json=(d,s=200)=>new Response(JSON.stringify(d),{status:s,headers:{'content-type':'application/json; charset=utf-8','cache-control':'no-store'}});
function authorized(req){try{const raw=(req.headers.get('cookie')||'').split(';').map(x=>x.trim()).find(x=>x.startsWith('lamsa_admin='))?.slice(12)||'';const [p,s]=raw.split('.');if(!p||!s)return false;const expected=createHmac('sha256',process.env.LAMSA_SESSION_SECRET||'').update(p).digest('hex');const a=Buffer.from(s),b=Buffer.from(expected);if(a.length!==b.length||!timingSafeEqual(a,b))return false;return JSON.parse(Buffer.from(p,'base64url').toString()).exp>Date.now()}catch{return false}}
export default async req=>{
 if(!authorized(req))return json({error:'انتهت الجلسة؛ سجل الدخول مجددًا'},401);
 const base=(process.env.LAMSA_STORE_URL||'https://lamsa-f1.netlify.app').replace(/\/$/,'');
 const action=new URL(req.url).searchParams.get('action');
 try{
  if(action==='products'&&req.method==='GET'){const r=await fetch(base+'/.netlify/functions/products',{cache:'no-store'});return new Response(await r.text(),{status:r.status,headers:{'content-type':'application/json','cache-control':'no-store'}})}
  if(action==='products'&&req.method==='POST'){const secret=process.env.LAMSA_PUBLISH_PASSWORD||'';if(!secret)return json({error:'أضف LAMSA_PUBLISH_PASSWORD في إعدادات موقع الإدارة؛ يجب أن تكون نفس كلمة النشر المضبوطة في موقع المتجر الأصلي.'},503);const body=await req.text();const r=await fetch(base+'/.netlify/functions/products',{method:'POST',headers:{'content-type':'application/json','authorization':'Bearer '+secret},body});return new Response(await r.text(),{status:r.status,headers:{'content-type':'application/json','cache-control':'no-store'}})}
  if(action==='orders'&&req.method==='GET'){const secret=process.env.LAMSA_PUBLISH_PASSWORD||'';if(!secret)return json({error:'أضف LAMSA_PUBLISH_PASSWORD في إعدادات موقع الإدارة.'},503);const r=await fetch(base+'/.netlify/functions/orders',{headers:{authorization:'Bearer '+secret},cache:'no-store'});return new Response(await r.text(),{status:r.status,headers:{'content-type':'application/json','cache-control':'no-store'}})}
  return json({error:'طلب غير مدعوم'},404);
 }catch(e){return json({error:'تعذر الاتصال بموقع المتجر. تحقق من إعدادات الربط.'},502)}
};

import { createHmac, timingSafeEqual } from 'node:crypto';
const json=(data,status=200)=>new Response(JSON.stringify(data),{status,headers:{'content-type':'application/json; charset=utf-8','cache-control':'no-store'}});
const eq=(a,b)=>{const x=Buffer.from(String(a||'')),y=Buffer.from(String(b||''));return x.length===y.length&&timingSafeEqual(x,y)};
const sign=(v)=>createHmac('sha256',process.env.LAMSA_SESSION_SECRET||'').update(v).digest('hex');
export default async req=>{
 if(req.method!=='POST')return json({error:'طريقة غير مدعومة'},405);
 try{const b=await req.json();const ok=eq(String(b.email||'').trim().toLowerCase(),(process.env.LAMSA_ADMIN_EMAIL||'').trim().toLowerCase())&&eq(b.password,process.env.LAMSA_ADMIN_PASSWORD)&&eq(String(b.code||'').trim(),String(process.env.LAMSA_ADMIN_CODE||'').trim());
 if(!ok)return json({error:'بيانات الدخول غير صحيحة'},401);
 const payload=Buffer.from(JSON.stringify({exp:Date.now()+8*60*60*1000})).toString('base64url');const token=payload+'.'+sign(payload);
 return new Response(JSON.stringify({ok:true}),{headers:{'content-type':'application/json','cache-control':'no-store','set-cookie':`lamsa_admin=${token}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=28800`}});
 }catch{return json({error:'تعذر التحقق من الدخول'},400)}
};

export default async()=>new Response(JSON.stringify({ok:true}),{headers:{'content-type':'application/json','set-cookie':'lamsa_admin=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0'}});

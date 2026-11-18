// Cloudflare Worker: private workbook and chart storage.
// Deploy separately from the existing public MOLIT API Worker.
// Required: R2 binding PRIVATE_FILES, ACCESS_TEAM_DOMAIN, ACCESS_AUD,
// ALLOWED_EMAIL, FRONTEND_ORIGIN. Protect this Worker with Cloudflare Access too.
const json=(v,status=200,headers={})=>new Response(JSON.stringify(v),{status,headers:{'content-type':'application/json; charset=utf-8',...headers}});
function b64url(v){const s=v.replace(/-/g,'+').replace(/_/g,'/');return Uint8Array.from(atob(s.padEnd(Math.ceil(s.length/4)*4,'=')),c=>c.charCodeAt(0))}
async function verifyAccess(request,env){
 const token=request.headers.get('Cf-Access-Jwt-Assertion');
 if(!token)throw Error('로그인이 필요합니다.');
 const parts=token.split('.');if(parts.length!==3)throw Error('잘못된 인증 토큰');
 const header=JSON.parse(new TextDecoder().decode(b64url(parts[0])));
 const claims=JSON.parse(new TextDecoder().decode(b64url(parts[1])));
 if(header.alg!=='RS256'||!header.kid)throw Error('지원하지 않는 인증 방식');
 const domain=env.ACCESS_TEAM_DOMAIN.replace(/^https?:\/\//,'').replace(/\/$/,'');
 const issuer='https://'+domain;
 if(claims.iss!==issuer||!(Array.isArray(claims.aud)?claims.aud.includes(env.ACCESS_AUD):claims.aud===env.ACCESS_AUD))throw Error('인증 대상이 일치하지 않습니다.');
 const now=Math.floor(Date.now()/1000);
 if(!claims.exp||claims.exp<=now||claims.nbf>now)throw Error('인증이 만료되었습니다.');
 if(!env.ALLOWED_EMAIL||String(claims.email||'').toLowerCase()!==env.ALLOWED_EMAIL.toLowerCase())throw Error('허용된 계정이 아닙니다.');
 const response=await fetch(issuer+'/cdn-cgi/access/certs');
 if(!response.ok)throw Error('인증서 조회 실패');
 const keys=(await response.json()).keys||[];
 const jwk=keys.find(k=>k.kid===header.kid);if(!jwk)throw Error('인증 키를 찾지 못했습니다.');
 const key=await crypto.subtle.importKey('jwk',jwk,{name:'RSASSA-PKCS1-v1_5',hash:'SHA-256'},false,['verify']);
 const ok=await crypto.subtle.verify('RSASSA-PKCS1-v1_5',key,b64url(parts[2]),new TextEncoder().encode(parts[0]+'.'+parts[1]));
 if(!ok)throw Error('인증 서명이 올바르지 않습니다.');
 return claims;
}
function cleanId(v){if(!/^[a-zA-Z0-9_-]{1,100}$/.test(v||''))throw Error('잘못된 파일 ID');return v}
export default {async fetch(request,env){
 const origin=request.headers.get('Origin');
 const allowed=env.FRONTEND_ORIGIN;
 const cors=origin&&origin===allowed?{'Access-Control-Allow-Origin':origin,'Vary':'Origin','Access-Control-Allow-Headers':'Content-Type, Cf-Access-Jwt-Assertion','Access-Control-Allow-Methods':'GET, POST, PUT, DELETE, OPTIONS'}:{};
 if(request.method==='OPTIONS')return new Response(null,{status:origin===allowed?204:403,headers:cors});
 if(!env.PRIVATE_FILES||!env.ACCESS_TEAM_DOMAIN||!env.ACCESS_AUD||!env.ALLOWED_EMAIL||!allowed)return json({error:'서버 설정 미완료'},503,cors);
 try{
  await verifyAccess(request,env);
  const url=new URL(request.url),path=url.pathname;
  if(path==='/api/private/files'&&request.method==='GET'){
   const listing=await env.PRIVATE_FILES.list({prefix:'workbooks/'});
   return json({files:listing.objects.map(o=>({id:o.key.slice('workbooks/'.length),size:o.size,uploaded:o.uploaded})),truncated:listing.truncated},200,cors);
  }
  if(path==='/api/private/files'&&request.method==='POST'){
   const file=await request.formData();const blob=file.get('file');
   if(!(blob instanceof File))return json({error:'파일을 선택해 주세요.'},400,cors);
   if(!/\.(xlsx|xls|csv)$/i.test(blob.name))return json({error:'엑셀·CSV만 허용합니다.'},400,cors);
   if(blob.size>20*1024*1024)return json({error:'20MB 이하 파일만 업로드할 수 있습니다.'},413,cors);
   const id=crypto.randomUUID();await env.PRIVATE_FILES.put('workbooks/'+id,blob.stream(),{httpMetadata:{contentType:'application/octet-stream'},customMetadata:{name:encodeURIComponent(blob.name)}});
   return json({id,name:blob.name},201,cors);
  }
  const match=path.match(/^\/api\/private\/files\/([^/]+)$/);
  if(match){const id=cleanId(match[1]),key='workbooks/'+id;
   if(request.method==='GET'){const o=await env.PRIVATE_FILES.get(key);if(!o)return json({error:'파일 없음'},404,cors);return new Response(o.body,{headers:{...cors,'content-type':'application/octet-stream','cache-control':'no-store','content-disposition':"attachment; filename*=UTF-8''"+(o.customMetadata?.name||'workbook.xlsx')}})}
   if(request.method==='DELETE'){await env.PRIVATE_FILES.delete(key);return json({ok:true},200,cors)}
  }
  if(path==='/api/private/charts'&&request.method==='GET'){
   const listing=await env.PRIVATE_FILES.list({prefix:'charts/'});
   const charts=await Promise.all(listing.objects.map(async o=>{const item=await env.PRIVATE_FILES.get(o.key);return item?await item.json():null}));
   return json({charts:charts.filter(Boolean),truncated:listing.truncated},200,cors);
  }
  if(path==='/api/private/charts'&&request.method==='POST'){
   const chart=await request.json();if(!chart||typeof chart.name!=='string'||!chart.name.trim())return json({error:'차트 이름 필요'},400,cors);
   const id=chart.id?cleanId(chart.id):crypto.randomUUID();
   const item={id,name:chart.name.slice(0,100),fileId:chart.fileId?cleanId(chart.fileId):null,sheet:String(chart.sheet||'').slice(0,100),settings:chart.settings||{},updatedAt:new Date().toISOString()};
   await env.PRIVATE_FILES.put('charts/'+id,JSON.stringify(item),{httpMetadata:{contentType:'application/json'}});
   return json(item,200,cors);
  }
  const chartMatch=path.match(/^\/api\/private\/charts\/([^/]+)$/);
  if(chartMatch&&request.method==='DELETE'){await env.PRIVATE_FILES.delete('charts/'+cleanId(chartMatch[1]));return json({ok:true},200,cors)}
  return json({error:'경로 없음'},404,cors);
 }catch(e){return json({error:e.message==='로그인이 필요합니다.'?e.message:'인증 또는 요청 처리 실패'},401,cors)}
}};

import {isIP} from 'node:net';

// Fixed upstream, no user-supplied URLs or IPs, no saved credentials,
// no router requests. The remote service sees the exit IP of the computer running RUX REAROUTER only.
// Its ASN/org is NOT proof of the user's contractual ISP or router WAN IP.
export const PUBLIC_IP_SOURCE='ipinfo.io';
export const PUBLIC_IP_ENDPOINT='https://ipinfo.io/json';

const field=(value,max=150)=>{
  if(typeof value!=='string')return null;
  const safe=value.trim();
  return safe&&safe.length<=max&&!/[\u0000-\u001f\u007f]/u.test(safe)?safe:null;
};
const validExitIp=raw=>{
  if(!raw||isIP(raw)===0)return false;
  if(isIP(raw)===4){
    const [a,b]=raw.split('.').map(Number);
    // Reject IANA special-use and documentation networks. Their addresses
    // cannot be presented as a publicly routed Internet exit.
    const [,,c]=raw.split('.').map(Number);
    if(a===0||a===10||a===127||a>=224||a===169&&b===254||
      a===172&&b>=16&&b<=31||a===192&&b===168||
      a===192&&b===0&&(c===0||c===2)||
      a===198&&(b===18||b===19||b===51&&c===100)||
      a===203&&b===0&&c===113||
      a===100&&b>=64&&b<=127)return false;
  }
  if(isIP(raw)===6){
    const s=raw.toLowerCase();
    // 2000::/3 is the global-unicast range, excluding the RFC 3849
    // documentation block and IPv4-mapped special-use addresses.
    if(!/^[23][0-9a-f]*:/u.test(s)||s.startsWith('2001:db8:')||
      s==='2001:db8'||s.startsWith('2001:0db8:')||
      s==='2001:0db8')return false;
  }
  return true;
};
export function normalizePublicConnection(raw){
  if(!raw||typeof raw!=='object'||Array.isArray(raw)||raw.error)return null;
  const ip=field(raw.ip,45);
  if(!validExitIp(ip))return null;
  const org=field(raw.org,140);
  const known=org?.match(/^AS(\d{1,10})(?:\s+(.+))?$/u);
  const hostname=field(raw.hostname,253);
  return {
    publicIp:ip,
    publicHost:hostname&&/^[a-z0-9_.-]+\.?$/iu.test(hostname)?hostname:null,
    networkOperator:known?.[2]||org||null,
    asn:known?.[1]?'AS'+known[1]:null,
    city:field(raw.city,100),
    region:field(raw.region,100),
    country:field(raw.country,64),
    timezone:field(raw.timezone,100),
    source:PUBLIC_IP_SOURCE,
    fetchedAt:new Date().toISOString(),
    classification:'public-egress-not-router-wan',
  };
}
export async function lookupPublicConnection({fetchImpl=fetch,timeoutMs=5000}={}){
  if(typeof fetchImpl!=='function'||!Number.isFinite(timeoutMs)||
    timeoutMs<100||timeoutMs>10000)throw Error('INVALID_PUBLIC_LOOKUP');
  const response=await fetchImpl(PUBLIC_IP_ENDPOINT,{method:'GET',redirect:'error',
    signal:AbortSignal.timeout(timeoutMs),
    headers:{Accept:'application/json'}});
  if(!response.ok||response.status!==200)throw Error('PUBLIC_LOOKUP_UNAVAILABLE');
  if(!String(response.headers.get('content-type')||'').toLowerCase().includes('json'))
    throw Error('PUBLIC_LOOKUP_INVALID');
  const length=Number(response.headers.get('content-length'));
  if(Number.isFinite(length)&&length>12288)throw Error('PUBLIC_LOOKUP_OVERSIZE');
  const chunks=[];let size=0;
  const reader=response.body?.getReader();
  if(!reader)throw Error('PUBLIC_LOOKUP_INVALID');
  try{
    while(true){
      const {done,value}=await reader.read();
      if(done)break;
      size+=value.byteLength;
      if(size>12288)throw Error('PUBLIC_LOOKUP_OVERSIZE');
      chunks.push(value);
    }
  }finally{reader.releaseLock();}
  const bytes=new Uint8Array(size);let i=0;
  for(const chunk of chunks){bytes.set(chunk,i);i+=chunk.byteLength;}
  let raw;
  try{raw=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(bytes));}
  catch{throw Error('PUBLIC_LOOKUP_INVALID');}
  const info=normalizePublicConnection(raw);
  if(!info)throw Error('PUBLIC_LOOKUP_INVALID');
  return info;
}


/**
 * Shared short-lived, memory-only cache for public egress metadata.
 * Competing modal openings reuse one HTTP request. A failure is never
 * cached, so retry is possible without restarting the manager.
 */
export function createPublicNetworkCache(lookup,{
  ttlMs=120_000,clock=Date.now
}={}){
  if(typeof lookup!=='function'||typeof clock!=='function'||
     !Number.isInteger(ttlMs)||ttlMs<1||ttlMs>300_000)
    throw Error('INVALID_PUBLIC_LOOKUP_CACHE');
  let cached=null,active=null;
  return async function publicConnection(){
    if(cached&&cached.until>clock())return cached.info;
    if(active)return active;
    const job=Promise.resolve().then(()=>lookup()).then(info=>{
      if(!info||typeof info!=='object'||
        info.classification!=='public-egress-not-router-wan'||
        typeof info.publicIp!=='string'||!validExitIp(info.publicIp))
        throw Error('PUBLIC_LOOKUP_INVALID');
      cached={info,until:clock()+ttlMs};
      return info;
    }).finally(()=>{if(active===job)active=null;});
    active=job;
    return job;
  };
}

import {createHash} from 'node:crypto';
import {isIP} from 'node:net';
import {routerOrigin} from './router-settings.mjs';
import {validateCallHistory} from './call-history.mjs';
import {callDateKey} from './public/history-view.mjs';
import {parseAutodialFields} from './autodial-core.mjs';
import {legacyCapturedAt,legacyReadStatus} from './public/legacy-readback.mjs';

const fail=code=>{throw Object.assign(new Error(code),{code});};
const hash=text=>createHash('sha256').update(text).digest('hex');
const MAX_HTML=32768;
const NATIVE_GET=new Set([
 '/index.htm','/firstlogin.htm','/login.htm','/top.htm','/status.htm',
 '/phones.htm','/cgi/cgi_phones.js','/cgi/cgi_info.js','/cgi/cgi_authpage.js',
 '/top_conn.xml','/status_conn.xml','/status.htm',
 // Loaded by the native phones.htm itself: its call-log poll and, after its
 // own sendForm(), the token renewal.
 '/call_log.xml','/cgi/renewPi.js',
]);
const ASSET=/^\/(?:js|css|images|lang)\/[a-z0-9_+./-]{1,110}$/i;
const allowedGet=pathname=>NATIVE_GET.has(pathname)||ASSET.test(pathname);
export function classifyRouterLogin({loginHtml,firstloginHtml}){
 if(typeof loginHtml!=='string'||typeof firstloginHtml!=='string'||
    loginHtml.length>MAX_HTML||firstloginHtml.length>MAX_HTML)
   fail('LEGACY_PROFILE_UNKNOWN');
 // The legacy page is a framed form with MD5 handled by its own script,
 // not the v6 form with ui_user. No values or secrets are examined.
 const legacy=
   /js\/loadScripts\.js/i.test(firstloginHtml) &&
   /<form\b[^>]*\bname=["']tF["']/i.test(firstloginHtml) &&
   /name=["']user["']/i.test(firstloginHtml) &&
   /name=["']ui_pws["']/i.test(firstloginHtml) &&
   /name=["']usr["']/i.test(firstloginHtml) &&
   /name=["']pws["']/i.test(firstloginHtml) &&
   /prepareLogin\s*\(/.test(firstloginHtml) &&
   /arc\.crypt\.md5\.hex/.test(firstloginHtml) &&
   /login\.cgi/.test(firstloginHtml) &&
   !/name=["']ui_user["']/.test(firstloginHtml);
 if(legacy)return {family:'livebox-fibra-legacy',status:'EXPERIMENTAL_READ_ONLY'};
 const modern=/js\/jquery-3\.6\.0\.min\.js/i.test(loginHtml)&&
   /name=["']ui_user["']/i.test(loginHtml)&&
   /name=["']ui_pws["']/i.test(loginHtml)&&
   /id=["']bt_save["']/i.test(loginHtml);
 if(modern)return {family:'livebox6-arcadyan',status:'SUPPORTED'};
 return {family:'unknown',status:'UNRECOGNIZED'};
}
async function boundedGet(origin,pathname,{fetchImpl=fetch,signal}={}){
 const target=new URL(pathname,origin);
 if(target.origin!==origin||!NATIVE_GET.has(target.pathname)||target.search||
    target.username||target.password)fail('LEGACY_PROFILE_UNKNOWN');
 let response;
 try{response=await fetchImpl(target.href,{method:'GET',redirect:'manual',
   headers:{'Accept':'text/html','Cache-Control':'no-store'},signal:signal||AbortSignal.timeout(5500)})}
 catch{fail('LEGACY_PROFILE_UNAVAILABLE')}
 if(response.status!==200||!response.body)fail('LEGACY_PROFILE_UNAVAILABLE');
 if(Number(response.headers.get('content-length'))>MAX_HTML){await response.body.cancel();fail('LEGACY_PROFILE_UNKNOWN')}
 const reader=response.body.getReader();
 let count=0;const chunks=[];
 try{
  for(;;){
   const {done,value}=await reader.read();
   if(done)break;
   count+=value.byteLength;
   if(count>MAX_HTML){await reader.cancel();fail('LEGACY_PROFILE_UNKNOWN')}
   chunks.push(value);
  }
 }finally{reader.releaseLock()}
 return new TextDecoder().decode(Buffer.concat(chunks,count));
}
export async function identifyRouter(ip,{fetchImpl=fetch,signal}={}){
 const origin=routerOrigin(ip);
 const loginHtml=await boundedGet(origin,'/login.htm',{fetchImpl,signal});
 // Modern v6/6+ redirects firstlogin.htm to login.htm and may return 302.
 // Classify it from login.htm before requesting the legacy-only page.
 const modern=classifyRouterLogin({loginHtml,firstloginHtml:''});
 let classification=modern;
 let firstloginHtml='';
 if(modern.family==='unknown'){
   firstloginHtml=await boundedGet(origin,'/firstlogin.htm',{fetchImpl,signal});
   classification=classifyRouterLogin({loginHtml,firstloginHtml});
 }
 // No firmware values, raw HTML or private identifiers are returned.
 return {schema:1,...classification,originScope:'configured-private-ip',
   fingerprint:hash(classification.family+':'+
     [loginHtml.includes('loadScripts.js'),loginHtml.includes('jquery-3.6.0.min.js'),
      firstloginHtml.includes('arc.crypt.md5.hex')].join(':'))};
}
export function safeNativeLoginRequest(r,origin){
 const u=new URL(r.url());
 if(u.origin!==origin||u.username||u.password||u.search||u.hash)return false;
 if(r.method()==='GET')return allowedGet(u.pathname);
 if(r.method()!=='POST'||u.pathname!=='/login.cgi')return false;
 const body=r.postData()||'';
 if(body.length>512)return false;
 const params=new URLSearchParams(body);
 const keys=[...params.keys()];
 // The visible native login password field must be disabled before submission.
 // Only the hashed native field may leave this isolated browser context.
 if(keys.length!==4||new Set(keys).size!==4||
    !['usr','pws','GO','login'].every(k=>params.has(k))||
    params.get('usr')!=='admin'||
    !/^[a-f0-9]{32}$/i.test(params.get('pws')||'')||
    params.get('GO')!=='status.htm')
   return false;
 return true;
}
export function isNativeLogout(r,origin){
 const u=new URL(r.url());
 return r.method()==='POST'&&u.origin===origin&&u.pathname==='/logout.cgi'&&
   !u.search&&!u.hash&&!u.username&&!u.password&&!r.postData();
}
// Serialized by Playwright into the isolated, already profile-checked router
// document. Runs AFTER the firmware's inline onsubmit handler.
export function installProtectedLegacySubmit(){
  const f=document.querySelector('form[name="tF"]');
  if(!f||typeof f.onsubmit!=='function')return false;
  f.addEventListener('submit',event=>{
    const visible=f.elements.namedItem('ui_pws'),
      user=f.elements.namedItem('usr'),digest=f.elements.namedItem('pws');
    if(!visible||!user||!digest||
       user.value!=='admin'||!/^[a-f0-9]{32}$/i.test(digest.value)||
       new URL(f.action).pathname!=='/login.cgi'){
      event.preventDefault();
      return;
    }
    visible.disabled=true;
  },{once:true});
  return true;
}

// Same-origin XHR in the actual topFrame, matching the firmware's own
// HTTP_Request('top_conn.xml','GET') behavior. Only minimal booleans/status
// cross to the Node backend: XML bodies, cookies and credential values do not.
// Strict one-shot HTTP outcome classifier. 2xx/3xx is merely an HTTP
// outcome; only a separate native status read can prove authentication.
export function validateLegacyPostOutcome({dispatched,blockedPosts,httpStatus}){
 if(!Number.isInteger(blockedPosts)||blockedPosts<0||!Number.isInteger(dispatched)||dispatched<0)
   fail('LEGACY_POST_HTTP_UNEXPECTED');
 if(blockedPosts!==0)fail('LEGACY_POST_NOT_ALLOWED');
 if(dispatched!==1)fail('LEGACY_POST_NOT_DISPATCHED');
 if(httpStatus===null)fail('LEGACY_POST_NO_HTTP_RESPONSE');
 if(!Number.isInteger(httpStatus)||httpStatus<100||httpStatus>599)
   fail('LEGACY_POST_HTTP_UNEXPECTED');
 if(httpStatus>=400&&httpStatus<=499)fail('LEGACY_POST_HTTP_4XX');
 if(httpStatus>=500&&httpStatus<=599)fail('LEGACY_POST_HTTP_5XX');
 if(![200,201,202,204,302,303].includes(httpStatus))
   fail('LEGACY_POST_HTTP_UNEXPECTED');
 return {httpResponseObserved:true,verifiedAuthentication:false};
}

export function nativeLegacySessionXHR(){
 return new Promise(resolve=>{
  let done=false;
  const finish=result=>{
    if(done)return;done=true;resolve(result);
  };
  try{
   const xhr=new XMLHttpRequest();
   xhr.open('GET','top_conn.xml',true);
   xhr.timeout=4500;
   xhr.setRequestHeader('If-Modified-Since','Wed, 15 Nov 1995 00:00:00 GMT');
   xhr.onreadystatechange=()=>{
     if(xhr.readyState!==4)return;
     if(xhr.status!==200){
       finish({kind:'HTTP_NON_200',status:xhr.status,authenticated:null});return;
     }
     try{
       const doc=new DOMParser().parseFromString(xhr.responseText,'application/xml');
       if(doc.querySelector('parsererror')){
         finish({kind:'XML_UNRECOGNIZED',status:200,authenticated:null});return;
       }
       const records=doc.getElementsByTagName('bUsrisLogined');
       if(records.length!==1||records[0].getAttribute('type')!=='int'){
         finish({kind:'XML_UNRECOGNIZED',status:200,authenticated:null});return;
       }
       const value=records[0].getAttribute('value');
       if(value==='1')finish({kind:'AUTHENTICATED',status:200,authenticated:true});
       else if(value==='-1'||value==='0')
         finish({kind:'NOT_AUTHENTICATED',status:200,authenticated:false});
       else finish({kind:'XML_UNRECOGNIZED',status:200,authenticated:null});
     }catch{
       finish({kind:'XML_UNRECOGNIZED',status:200,authenticated:null});
     }
   };
   xhr.onerror=()=>finish({kind:'NETWORK_ERROR',status:0,authenticated:null});
   xhr.ontimeout=()=>finish({kind:'TIMEOUT',status:0,authenticated:null});
   xhr.send(null);
  }catch{
   finish({kind:'NETWORK_ERROR',status:0,authenticated:null});
  }
 });
}

export function loginStatusValue(xml){
 // The older firmware uses self-closing XML nodes with type/value attributes.
 if(typeof xml!=='string'||xml.length>12000)return null;
 // This firmware includes commented-out examples of login states.
 // Ignore XML comments, otherwise a commented successful state would
 // be misinterpreted as a live authenticated session.
 const active=xml.replace(/<!--[\s\S]*?-->/g,'');
 const tags=[...active.matchAll(/<bUsrisLogined\b[^>]{0,110}\/>/gi)];
 if(tags.length!==1)return null;
 const type=/\btype=["']([^"']+)["']/i.exec(tags[0][0])?.[1];
 const value=/\bvalue=["'](-?[0-9]{1,3})["']/i.exec(tags[0][0])?.[1];
 if(type!=='int')return null;
 return value==='1'?true:value==='-1'||value==='0'?false:null;
}
export function inspectLegacyTelephoneFields(body){
 if(typeof body!=='string'||Buffer.byteLength(body,'utf8')>65536)
   fail('LEGACY_PHONE_SCHEMA');
 const rows=[...body.matchAll(/addCfg\(\s*"([a-zA-Z][a-zA-Z0-9_]{0,70})"\s*,/g)];
 const names=rows.map(x=>x[1]);
 const expected=['LineEnable1','LineEnable2','hotLineEnable1','hotLineNumber1',
   'hotLineTimeout1'];
 if(rows.length<10||rows.length>90||new Set(names).size!==names.length||
    expected.some(name=>!names.includes(name)))fail('LEGACY_PHONE_SCHEMA');
 // DO NOT return values (telephone numbers, account identifiers etc.).
 return {fieldCount:names.length,hasHotline:true,
   callHistory:false,blocking:false,dns:false,ringTest:false,
   autodialWrite:false,configurationPosts:0};
}

// Native Arcadyan data file: addCfg("name",numericId,'escaped value');
// Every addCfg call must match, otherwise the whole file is unrecognized.
const CFG_ROW=/addCfg\(\s*"([A-Za-z][A-Za-z0-9_]{0,70})"\s*,\s*(?:"(\d{1,12})"|(\d{1,12}))\s*,\s*(?:'([^'\\\r\n]{0,1024})'|"([^"\\\r\n]{0,1024})")\s*\)/g;
export function parseLegacyCfg(body){
 if(typeof body!=='string'||Buffer.byteLength(body,'utf8')>262144)fail('LEGACY_CFG_SCHEMA');
 const rows=[...body.matchAll(CFG_ROW)];
 if(!rows.length||rows.length!==(body.match(/\baddCfg\s*\(/g)||[]).length)fail('LEGACY_CFG_SCHEMA');
 const cfg=new Map();
 for(const m of rows){
  if(cfg.has(m[1]))fail('LEGACY_CFG_SCHEMA');
  let value;
  // Firmware getCfg(): unescape(unescape(raw)).
  try{value=unescape(unescape(m[4]??m[5]))}catch{fail('LEGACY_CFG_SCHEMA')}
  cfg.set(m[1],{id:Number(m[2]??m[3]),value});
 }
 return cfg;
}
// Page dependencies as loadScripts.js reads them: var scripts={cgi:[...]}.
// Only literal identifiers are accepted; page JavaScript is never evaluated.
export function parseLegacyScriptsCgi(html){
 if(typeof html!=='string')return null;
 const block=/\bvar\s+scripts\s*=\s*\{([^{}]{0,800})\}/.exec(html.replace(/<!--[\s\S]*?-->/g,''));
 const list=block&&/(?:^|[\s,{])["']?cgi["']?\s*:\s*\[([^\]]{0,600})\]/.exec(block[1]);
 if(!list||!/^\s*(?:["'][a-z0-9_]{0,48}["']\s*,?\s*){0,24}$/i.test(list[1]))return null;
 return [...list[1].matchAll(/["']([a-z0-9_]{0,48})["']/gi)].map(x=>x[1])
   .filter(name=>/^[a-z][a-z0-9_]{0,47}$/i.test(name));
}
const flag=value=>value==='1'?true:value==='0'?false:null;
// Field names verified in the authenticated cgi_phones.js of fw v1.03.05.229B-ES.
export function readLegacyPhone(cfg){
 const v=name=>cfg.get(name)?.value;
 const number=v('hotLineNumber1'),seconds=v('hotLineTimeout1');
 const autodial={
  enabled:flag(v('hotLineEnable1')),
  number:typeof number==='string'&&/^[0-9*#+]{0,32}$/.test(number)?number:null,
  seconds:typeof seconds==='string'&&/^[0-9]{1,3}$/.test(seconds)?Number(seconds):null
 };
 autodial.verified=autodial.enabled!==null&&autodial.number!==null&&autodial.seconds!==null;
 // phones.htm shows a line as active from regStatusN (VoIP registration).
 const lineNumber=line=>{const value=v('userId'+line);
   return typeof value==='string'&&/^\+?[0-9]{0,20}$/.test(value)?value:null;};
 return {autodial,lines:[1,2].map(line=>({line,enabled:flag(v('LineEnable'+line)),
   registered:flag(v('regStatus'+line)),number:lineNumber(line)})),fieldCount:cfg.size};
}
// call_log.xml as read by phones.htm: <CallLog type="array" value="[['escaped'],...,null]"/>.
// Parsed literally (the firmware itself evaluates it). Native type 1 is
// caller -> own line (agency); type 2 is own line -> callee; missed rows use endtime.
const LOG_ROW=/^index=(\d{1,7}),type=(\d),caller=([^,]{0,64}),callee=([^,]{0,64}),agency=([^,]{0,64}),duration=(\d{1,7}),missedcall=([01]),starttime=([^,]{0,40}),answertime=([^,]{0,40}),endtime=([^,]{0,40})$/;
const LOG_TIME=/^(\d{2})\/(\d{2})\/(\d{4}) (\d{2}):(\d{2}):\d{2}$/;
const XML_ENTITY={quot:'"',apos:"'",lt:'<',gt:'>',amp:'&'};
const span=n=>{const h=Math.floor(n/3600),m=Math.floor(n%3600/60);return (h?h+'h':'')+(h||m?m+'m':'')+(n%60)+'s'};
/**
 * Recognize exactly the native clear-all action declared by phones.htm.
 * This is a source-code preflight only: it never executes a page function.
 */
export function hasNativeLegacyClearLog(html){
 if(typeof html!=='string'||Buffer.byteLength(html,'utf8')>131072)return false;
 const source=html.replace(/<!--[\s\S]*?-->/g,'');
 const begin=source.search(/\bfunction\s+ClearLog\s*\(\s*\)\s*\{/);
 if(begin<0)return false;
 const scope=source.slice(begin,begin+1500);
 return /\bsetCfg\s*\(\s*["']clearlog["']\s*,\s*1\s*\)/.test(scope)&&
   /\bsendForm\s*\(\s*["']phones\.htm["']\s*,\s*["']["']\s*,\s*["']["']\s*\)/.test(scope);
}

export function parseLegacyCallLog(xml,capturedAt=new Date().toISOString()){
 if(typeof xml!=='string'||Buffer.byteLength(xml,'utf8')>131072)fail('CALL_LOG_SCHEMA');
 const tags=[...xml.replace(/<!--[\s\S]*?-->/g,'').matchAll(/<CallLog\b([^>]*)\/>/g)];
 const raw=tags.length===1&&/\btype="array"/.test(tags[0][1])?/\bvalue="([^"]*)"/.exec(tags[0][1])?.[1]:undefined;
 if(raw===undefined)fail('CALL_LOG_SCHEMA');
 const value=raw.replace(/&(quot|apos|lt|gt|amp);/g,(_,e)=>XML_ENTITY[e]);
 if(!/^\[(?:\s*\['[^'\\]*'\]\s*,)*\s*null\s*\]$/.test(value))fail('CALL_LOG_SCHEMA');
 const rows=[...value.matchAll(/\['([^'\\]*)'\]/g)].map((m,index)=>{
  let text;try{text=unescape(m[1])}catch{fail('CALL_LOG_SCHEMA')}
  const r=LOG_ROW.exec(text);
  // Native type 0 was never observed; it is not guessed.
  if(!r||!['1','2'].includes(r[2])||(r[7]==='1'&&r[2]!=='1'))fail('CALL_LOG_SCHEMA');
  const [,,type,caller,callee,agency,seconds,missed,start,,end]=r;
  const when=LOG_TIME.exec(missed==='1'?end:start);
  if(!when)fail('CALL_LOG_SCHEMA');
  const call={type:missed==='1'?'MISS':type==='1'?'IN':'OUT',
   dateTime:`${when[1]}.${when[2]}.${when[3]} ${when[4]}:${when[5]}`,duration:span(Number(seconds)),
   source:type==='1'?caller:agency,destination:type==='1'?agency:callee};
  call.selectable=call.type!=='OUT'&&/^[0-9]{1,32}$/.test(call.source);
  return {call,index,key:callDateKey(call)};
 });
 // The native ring buffer is not ordered; newest first, like the modern view.
 const calls=rows.sort((a,b)=>(a.key<b.key?1:a.key>b.key?-1:0)||b.index-a.index).map(x=>x.call);
 return validateCallHistory({capturedAt,total:calls.length,calls,truncated:false});
}
// cgi_dns.js arrays used by advanced_network_dns.htm (read-only fields there).
const stringRows=(body,name)=>{
 const m=new RegExp(String.raw`\bvar\s+${name}\s*=\s*\[((?:\s*(?:\['[^'\\]*'\]|'[^'\\]*')\s*,)*)\s*null\s*\]\s*;`).exec(body);
 return m?[...m[1].matchAll(/'([^'\\]*)'/g)].map(x=>unescape(x[1])):null;
};
export function readLegacyDns(body){
 if(typeof body!=='string')fail('LEGACY_DNS_SCHEMA');
 const wan=stringRows(body,'wanConnStatus'),ip4=stringRows(body,'ip4_info_list'),
   wan6=stringRows(body,'wan6ConnStatus'),rdns=stringRows(body,'status_ip6_rdns');
 if(!wan||!ip4||!wan6||!rdns||!wan.length||wan.length!==ip4.length)fail('LEGACY_DNS_SCHEMA');
 const ip=(v,version)=>{
  if(v===undefined||v===''||v==='0'||v==='0.0.0.0'||v==='::')return null;
  if(isIP(v)!==version)fail('LEGACY_DNS_SCHEMA');
  return v;
 };
 // Native 229B WAN status fields are separated by ';'. Keep the comma form
 // accepted by earlier adapters, but require an explicit known state.
 const connected=s=>/^connected(?:[;,]|$)/.test(s);
 const connection=rows=>rows.some(connected)?true:
   rows.length&&rows.every(s=>/^disconnected(?:[;,]|$)/.test(s))?false:null;
 const i=wan.findIndex(connected),f=i<0?[]:ip4[i].split(';');
 if(i>=0&&f.length<5)fail('LEGACY_DNS_SCHEMA');
 if(connection(wan)===null&&connection(wan6)===null)fail('LEGACY_DNS_SCHEMA');
 return {ipv4:{connected:connection(wan),primary:ip(f[3],4),secondary:ip(f[4],4)},
  ipv6:{connected:connection(wan6),primary:ip(rdns[0],6),secondary:ip(rdns[1],6)}};
}
export function readLegacyDevice(body){
 if(typeof body!=='string')fail('LEGACY_DEVICE_SCHEMA');
 // Native CGI string literals use Arcadyan percent escaping, including
 // dots and hyphens in the firmware version. Decode only this allowlist.
 const values=[...body.matchAll(/\bvar\s+fw_ver\s*=\s*["']((?:[a-zA-Z0-9._-]|%[a-fA-F0-9]{2}){1,192})["']\s*;/g)];
 if(values.length!==1)fail('LEGACY_DEVICE_SCHEMA');
 let firmware;
 try{firmware=decodeURIComponent(values[0][1])}catch{fail('LEGACY_DEVICE_SCHEMA')}
 if(!/^[a-zA-Z0-9._-]{1,64}$/.test(firmware))fail('LEGACY_DEVICE_SCHEMA');
 return {firmware,source:'native-info-cgi'};
}
// Arcadyan arc.str.escape: every non-alphanumeric character becomes %XX.
export const arcEscape=value=>String(value).replace(/[^0-9A-Za-z]/g,c=>'%'+c.charCodeAt(0).toString(16).toUpperCase().padStart(2,'0'));
// Exactly what phones.htm sendForm("phones.htm","","") posts to /apply.cgi.
// Returns the names of the failed checks (empty = exact match); never values.
export function nativeApplyMismatch(body,expected){
 if(typeof body!=='string'||body.length>2048||!(expected instanceof Set)||!expected.size)return ['BODY'];
 const p=new URLSearchParams(body),keys=[...p.keys()];
 const sets=keys.filter(k=>/^SET\d{1,2}$/.test(k));
 const pi=p.get('pi')||'';
 return Object.entries({
  KEYS:new Set(keys).size===keys.length&&keys.length===sets.length+3&&sets.every((k,i)=>k==='SET'+i),
  CMD:p.get('CMD')==='',GO:p.get('GO')==='phones.htm',
  PI:/^[\x20-\x7e]{1,256}$/.test(pi)&&pi!=='-1',
  SET_COUNT:sets.length===expected.size,
  SET_VALUES:sets.every(k=>expected.has(p.get(k)))
 }).filter(([,ok])=>!ok).map(([name])=>name);
}
export const matchesNativeApply=(body,expected)=>nativeApplyMismatch(body,expected).length===0;
// The only native fields RuxBox+ may set, all on phones.htm of this firmware.
const APPLY_FIELDS=new Set(['hotLineEnable1','hotLineEnable2','hotLineNumber1','hotLineNumber2',
 'hotLineTimeout1','hotLineTimeout2','ring_test','clearlog']);
const AUTODIAL_NAMES=Object.freeze({
 phone_hotline_enable_0:'hotLineEnable1',phone_hotline_enable_1:'hotLineEnable2',
 phone_hotline_number_0:'hotLineNumber1',phone_hotline_number_1:'hotLineNumber2',
 phone_hotline_timeout_0:'hotLineTimeout1',phone_hotline_timeout_1:'hotLineTimeout2'});
// Same two-field-per-setting structure as the modern profile, legacy ids.
// This firmware renumbers addCfg ids at every login (stable within one
// session), so the revision covers names and values only.
export function legacyAutodialSnapshot(cfg){
 const snapshot=parseAutodialFields(Object.entries(AUTODIAL_NAMES).map(([name,legacy])=>
   [name,cfg.get(legacy)?.id,cfg.get(legacy)?.value]));
 return Object.freeze({...snapshot,revision:hash(JSON.stringify(snapshot.rows.map(r=>[r.name,r.value])))});
}
export const legacyAutodialField=name=>AUTODIAL_NAMES[name];
// Telephony settings of cgi_phones.js by name and value (ids are renumbered
// per login). Live registration state and one-shot action fields are excluded.
const PHONE_VOLATILE=new Set(['regStatus1','regStatus2','clearlog','ring_test']);
export const legacyPhoneSettingsRevision=cfg=>hash(JSON.stringify([...cfg]
  .filter(([name])=>!PHONE_VOLATILE.has(name)).map(([name,c])=>[name,c.value])
  .sort(([a],[b])=>a<b?-1:a>b?1:0)));
// Pages listed by the native menu; referenced tabs are added only when a read
// page names them and they do not look like an action, token or upgrade page.
const LEGACY_PAGES=new Set(['/phones.htm','/softphones.htm','/status.htm',
 '/advanced_network_dns.htm','/advanced_network_wan.htm','/advanced_network_configuration.htm',
 '/advanced_firewall.htm','/support_information.htm']);
const UNSAFE_NAME=/reboot|restart|reset|factory|upgrade|firmware|restore|backup|log(?:in|out)|wait|apply|renew|token|wizard|setup|pin|delete|remove|clear|test|ring/i;
const MAX_NATIVE_BODY=262144,MAX_SESSION_GETS=48;
// Bounded GET-only reader over the authenticated browser context. Pages may
// declare CGIs; only declared, non-action names can then be read.
export function createLegacyReader(ctx,origin,signal){
 let valid=false;
 try{valid=routerOrigin(new URL(origin).hostname)===origin}catch{}
 if(!valid)fail('LEGACY_PROFILE_UNKNOWN');
 // Verified declarations: phones.htm -> cgi phones + call_log.xml; DNS page -> cgi dns.
 const pages=new Set(LEGACY_PAGES),cgis=new Set(['phones','dns','info']),resources=new Set(['/call_log.xml']);
 let gets=0;
 const read=async pathname=>{
  if(signal?.aborted||++gets>MAX_SESSION_GETS)fail('LEGACY_READ_BUDGET');
  const response=await ctx.request.get(origin+pathname,{timeout:6000,maxRedirects:0});
  const status=response.status();
  if(status!==200)return {status,body:null};
  const declared=response.headers()?.['content-length'];
  if(declared!==undefined&&(!/^\d{1,9}$/.test(String(declared))||Number(declared)>MAX_NATIVE_BODY))
    return {status,body:null,reason:'SIZE_LIMIT'};
  const bytes=await response.body();
  if(bytes.length>MAX_NATIVE_BODY)return {status,body:null,reason:'SIZE_LIMIT'};
  let body;
  try{body=new TextDecoder('utf-8',{fatal:true}).decode(bytes)}
  catch{body=new TextDecoder('latin1').decode(bytes)}
  return {status,body};
 };
 return {
  async page(pathname){
   if(!pages.has(pathname))fail('LEGACY_READ_NOT_ALLOWED');
   const result=await read(pathname);
   if(result.body===null)return result;
   const html=result.body.replace(/<!--[\s\S]*?-->/g,'');
   for(const name of parseLegacyScriptsCgi(html)||[])if(!UNSAFE_NAME.test(name))cgis.add(name);
   for(const m of html.matchAll(/["'\/]([a-z][a-z0-9_]{0,48}\.htm)["'?#]/gi))
     if(!UNSAFE_NAME.test(m[1])&&pages.size<24)pages.add('/'+m[1]);
   for(const m of html.matchAll(/["'](\/?(?:cgi\/)?[a-z][a-z0-9_]{0,40}\.xml)["']/gi))
     if(!UNSAFE_NAME.test(m[1])&&resources.size<8)resources.add('/'+m[1].replace(/^\//,''));
   return {...result,cgi:parseLegacyScriptsCgi(html)};
  },
  async cgi(name){
   if(!cgis.has(name))fail('LEGACY_READ_NOT_ALLOWED');
   return read('/cgi/cgi_'+name+'.js');
  },
  async resource(pathname){
   if(!resources.has(pathname))fail('LEGACY_READ_NOT_ALLOWED');
   return read(pathname);
  },
  known:()=>({pages:[...pages],cgis:[...cgis],resources:[...resources]})
 };
}

export function inspectNativeLegacyFormShape(){
 const form=document.querySelector('form[name="tF"]');
 const visibleUser=form?.elements.namedItem('user');
 const visiblePassword=form?.elements.namedItem('ui_pws');
 const nativeUser=form?.elements.namedItem('usr');
 const nativeHash=form?.elements.namedItem('pws');
 let actionValid=false;
 try{actionValid=!!form && new URL(form.action).pathname==='/cgi-bin/login.exe'}catch{}
 const flags={
   form:!!form,
   method:form?.method.toUpperCase()==='POST',
   action:actionValid,
   user:!!visibleUser,
   userDisabled:visibleUser?.disabled===true,
   userAdmin:visibleUser?.value==='admin',
   passwordField:!!visiblePassword,
   passwordEnabled:visiblePassword?.disabled===false,
   nativeUser:!!nativeUser,
   nativeHash:!!nativeHash,
   prepareLogin:typeof prepareLogin==='function',
   md5:typeof arc?.crypt?.md5?.hex==='function',
   topCheck:typeof top.checkTopConnect==='function',
   topNext:top.G_next==='status.htm'
 };
 const missing=Object.keys(flags).filter(name=>flags[name]!==true);
 return {ready:missing.length===0,missing};
}

export async function loginLegacyFibra({ip,password,chromium,executablePath,signal,onPhase,inspect,operation}){
 const phase=label=>{try{if(typeof onPhase==='function')onPhase(label)}catch{}};
 phase('ENTER');
 if(typeof password!=='string'||!password||password.length>256||
    !chromium||typeof executablePath!=='string')fail('CREDENTIAL_REQUIRED');
 const origin=routerOrigin(ip);
 // The classifier is read-only. Unknown firmwares never receive a password.
 const probe=await identifyRouter(ip,{signal});
 if(probe.family!=='livebox-fibra-legacy')fail('LEGACY_PROFILE_UNKNOWN');
 let browser,ctx;
 let dispatched=0,blockedPosts=0;
 let authPostHttpStatus=null;
 let loggingOut=false,logoutDispatched=0,page;
 // At most one native /apply.cgi POST, only while a matching permit exists.
 let applyPermit=null,applyDispatched=0,applyBlocked=0,applyStatus=null,operating=false;
 // Firmware's own logout: topFrame form tF_Logout, POST logout.cgi, no fields.
 // Returns true only when the native status read reports no admin session.
 const closeSession=async()=>{
  if(loggingOut||!page)return false;
  loggingOut=true;
  const submitted=await page.frame({name:'topFrame'})?.evaluate(()=>{
    const f=document.forms.tF_Logout;
    if(!f||f.elements.length!==0||new URL(f.action).pathname!=='/logout.cgi')return false;
    f.submit();return true;
  }).catch(()=>false);
  if(!submitted)return false;
  for(const delay of [400,800,1500]){
    await page.waitForTimeout(delay);
    const check=await page.frame({name:'topFrame'})?.evaluate(nativeLegacySessionXHR).catch(()=>null);
    if(check?.kind==='NOT_AUTHENTICATED')return logoutDispatched===1;
  }
  return false;
 };
 try{
  browser=await chromium.launch({headless:true,executablePath,
   args:['--disable-background-networking','--disable-sync','--no-first-run'],timeout:12000});
  ctx=await browser.newContext({acceptDownloads:false,serviceWorkers:'block'});
  await ctx.route('**/*',async route=>{
   const r=route.request(),u=new URL(r.url());
   if(isNativeLogout(r,origin)&&loggingOut&&logoutDispatched===0){
     logoutDispatched=1;
     return route.continue();
   }
   if(r.method()==='POST'&&u.origin===origin&&u.pathname==='/apply.cgi'&&!u.search){
     const mismatch=applyPermit?nativeApplyMismatch(r.postData()||'',applyPermit):['NO_PERMIT'];
     if(applyDispatched===0&&!mismatch.length){
       applyDispatched=1;return route.continue();
     }
     applyBlocked++;phase('APPLY_REJECTED_'+(mismatch[0]||'SECOND_POST'));
     return route.abort();
   }
   if(!safeNativeLoginRequest(r,origin)){
     if(r.method()==='POST')blockedPosts++;
     return route.abort();
   }
   if(r.method()==='POST'){
     if(dispatched!==0)return route.abort();
     dispatched=1;
   }
   return route.continue();
  });
  phase('BROWSER_CONTEXT_READY');
  page=await ctx.newPage();
  // Observe ONLY the HTTP status of the one permitted login POST; no
  // request body, headers, cookie, redirected URL or password is recorded.
  page.on('response',response=>{
    try{
      const request=response.request(),u=new URL(response.url());
      if(request.method()==='POST'&&u.origin===origin&&u.pathname==='/login.cgi'){
        authPostHttpStatus=response.status();
      }
      if(request.method()==='POST'&&u.origin===origin&&u.pathname==='/apply.cgi')
        applyStatus=response.status();
    }catch{}
  });
  await page.goto(origin+'/index.htm',{waitUntil:'domcontentloaded',timeout:12000});
  phase('INDEX_LOADED');
  const frame=page.frame({name:'mainFrame'});
  if(!frame)fail('LEGACY_LOGIN_FORM_UNKNOWN');
  // Let index.htm complete its native navigation to firstlogin.htm.
  // A second forced navigation races its scripts and may reset the form.
  try{
    await frame.locator('input[name="ui_pws"]:not([disabled])').waitFor({
      state:'visible',timeout:14000
    });
  }catch{fail('LEGACY_LOGIN_FORM_UNKNOWN')}
  phase('PASSWORD_FIELD_VISIBLE');
  if(new URL(frame.url()).pathname!=='/firstlogin.htm')
    fail('LEGACY_LOGIN_FORM_UNKNOWN');
  const expected=['input[name="user"]','input[name="ui_pws"]',
    'input[name="usr"]','input[name="pws"]','#bt_save'];
  for(const selector of expected)
    if(await frame.locator(selector).count()!==1)fail('LEGACY_LOGIN_FORM_UNKNOWN');
  // The firmware pre-populates 'admin' in a DISABLED input.
  // Trying to fill it made Playwright wait forever, even with a valid password.
  // The firmware can render a visible password field before its JavaScript
  // login state finishes initializing. Wait for ALL original invariants;
  // do not weaken validation, click, submit, or repeat a login attempt.
  phase('SELECTORS_VERIFIED');
  let shapeReady=false;
  for(const pause of [0,120,250,500,800]){
    if(signal?.aborted)fail('LEGACY_LOGIN_FORM_UNKNOWN');
    if(pause)await page.waitForTimeout(pause);
    const state=await frame.evaluate(inspectNativeLegacyFormShape).catch(()=>null);
    if(state?.ready===true&&Array.isArray(state.missing)&&state.missing.length===0){
      shapeReady=true;break;
    }
  }
  if(!shapeReady)fail('LEGACY_LOGIN_FORM_UNKNOWN');
  phase('FORM_SHAPE_VERIFIED');
  // The inline native onsubmit handler first hashes the typed password into
  // 'pws'. This late listener then disables the visible 'ui_pws' input BEFORE
  // the browser serializes the form. Never transmit the plaintext input.
  const protectedForm=await frame.evaluate(installProtectedLegacySubmit).catch(()=>false);
  if(!protectedForm)fail('LEGACY_LOGIN_FORM_UNKNOWN');
  await frame.locator('input[name="ui_pws"]').fill(password);
  // A single explicit user-initiated action. Never submit again on timeout.
  // The route handler sees the form POST only AFTER click() resolves, so the
  // outcome is awaited here; 'dispatched' is still 0 when click() returns.
  let clickFailed=false;
  phase('BUTTON_CLICK_STARTED');
  try{await frame.locator('#bt_save').click({timeout:8500})}catch{clickFailed=true}
  for(let i=0;i<40&&blockedPosts===0&&authPostHttpStatus===null;i++){
    if(signal?.aborted)fail('LEGACY_POST_NO_HTTP_RESPONSE');
    await page.waitForTimeout(150);
  }
  if(clickFailed&&dispatched===0)fail('LEGACY_LOGIN_FORM_UNKNOWN');
  phase('POST_OUTCOME_CHECK');
  validateLegacyPostOutcome({dispatched,blockedPosts,httpStatus:authPostHttpStatus});
  // The firmware itself checks status from the topFrame with XHR, including
  // If-Modified-Since and browser-origin request headers. APIRequestContext
  // shares cookies but does not reproduce these request semantics.
  // One login dispatch, bounded GET-only session checks.
  let verified=false,observedExplicitFailure=false,observedTransportFailure=false;
  for(const delay of [200,650,1250]){
    if(signal?.aborted)fail('LEGACY_READBACK_UNAVAILABLE');
    await page.waitForTimeout(delay);
    try{
      const topFrame=page.frame({name:'topFrame'});
      if(!topFrame||new URL(topFrame.url()).pathname!=='/top.htm'){
        observedTransportFailure=true;continue;
      }
      const check=await topFrame.evaluate(nativeLegacySessionXHR);
      if(check?.kind==='AUTHENTICATED'&&check.authenticated===true){
        verified=true;break;
      }
      if(check?.kind==='NOT_AUTHENTICATED')observedExplicitFailure=true;
      else observedTransportFailure=true;
    }catch{
      observedTransportFailure=true;
    }
  }
  if(!verified)fail(observedExplicitFailure?'LEGACY_READBACK_NOT_AUTHENTICATED':
    'LEGACY_READBACK_UNAVAILABLE');
  phase('LOGIN_VERIFIED');
  const attemptedAt=new Date().toISOString();
  const reader=createLegacyReader(ctx,origin,signal);
  const requireBody=res=>{
   if(res.body!==null)return res.body;
   fail(res.reason==='SIZE_LIMIT'?'LEGACY_READ_SIZE_LIMIT':
     'LEGACY_READ_HTTP_'+res.status);
  };
  const phoneCfg=async()=>{
    const res=await reader.cgi('phones');
   const body=requireBody(res);
   inspectLegacyTelephoneFields(body);
   return parseLegacyCfg(body);
  };
  const callLog=async()=>{
    const res=await reader.resource('/call_log.xml');
   return parseLegacyCallLog(requireBody(res),new Date().toISOString());
  };
  // One write on the native phones.htm, through its own setCfg()/sendForm().
  // Never throws after dispatch: the caller must learn that a POST was sent.
  const nativeApply=async(fields,beforeDispatch)=>{
    // A clear-all request can never be bundled with an unrelated setting.
    if(!Array.isArray(fields)||!fields.length||
      (fields.some(([n])=>n==='clearlog')&&
       (fields.length!==1||fields[0][0]!=='clearlog'||fields[0][1]!=='1')))
      fail('LEGACY_APPLY_INVALID');
    const cfg=await phoneCfg();
    const changed=fields.filter(([name,value])=>{
      if(!APPLY_FIELDS.has(name)||typeof value!=='string'||!/^[0-9+*#-]{0,32}$/.test(value)||!cfg.has(name))
        fail('LEGACY_APPLY_INVALID');
      return cfg.get(name).value!==value;
    });
    if(!changed.length)fail('LEGACY_APPLY_INVALID');
    const main=page.frame({name:'mainFrame'});
    try{
      await main.goto(origin+'/phones.htm',{waitUntil:'domcontentloaded',timeout:12000});
      await main.waitForFunction(()=>typeof setCfg==='function'&&typeof sendForm==='function'&&
        typeof getCfg==='function'&&getCfg('ring_test')!==undefined&&
        !!document.querySelector('meta[name="pi"]')?.content,null,{timeout:12000});
    }catch{fail('LEGACY_APPLY_FORM')}
    if(new URL(main.url()).pathname!=='/phones.htm')fail('LEGACY_APPLY_FORM');
    // Ids are renumbered when phones.htm is served: stage the values in the
    // page's own cfg and permit exactly the ids it reports for these names.
    const staged=await main.evaluate(list=>list.map(([n,v])=>{
      const c=setCfg(n,v);return c?{id:String(c.id),value:c.value,dirty:c.isDirty}:null;
    }),changed).catch(()=>null);
    if(!Array.isArray(staged)||staged.length!==changed.length||
       staged.some((s,i)=>!s?.dirty||!/^[0-9]{1,12}$/.test(s.id)||s.value!==arcEscape(changed[i][1]))||
       new Set(staged.map(s=>s.id)).size!==staged.length)fail('LEGACY_APPLY_FORM');
    applyPermit=new Set(staged.map(s=>s.id+'='+s.value));
    if(typeof beforeDispatch==='function')await beforeDispatch();
    phase('APPLY_DISPATCH');
    await main.evaluate(()=>{sendForm('phones.htm','','')}).catch(()=>{});
    for(let i=0;i<60&&applyStatus===null&&applyBlocked===0;i++)await page.waitForTimeout(150);
    applyPermit=null;
    phase(applyDispatched?'APPLY_RESPONSE':'APPLY_NOT_SENT');
    return {configurationPosts:applyDispatched,
      response:{status:applyStatus,transportError:applyStatus===null}};
  };
  // Unrecognized data is reported as unverified, never as empty or disabled.
  const optional=async fn=>{try{return await fn()}catch{return null}};
  const reads={};
  const readSection=async(key,fn)=>{
   try{
    const value=await fn();
    reads[key]={status:'VERIFIED',capturedAt:new Date().toISOString()};
    return value;
   }catch(error){
    const code=/^(?:LEGACY_|CALL_LOG_)[A-Z0-9_]{1,60}$/.test(error?.code||'')
      ?error.code:'LEGACY_READ_COMMUNICATION';
    reads[key]={status:/SCHEMA|HTTP_404|SIZE_LIMIT/.test(code)?'UNAVAILABLE':'ERROR',code};
    return null;
   }
  };
  let data,clearHistory=false,cfg=null;
  if(typeof operation==='function'){
    operating=true;
    data={operation:await operation({reader,phoneCfg,callLog,nativeApply})};
    operating=false;
  }else{
   data={phone:await readSection('phone',async()=>{
     cfg=await phoneCfg();const phone=readLegacyPhone(cfg);
     if(!phone.autodial.verified&&!phone.lines.some(line=>line.enabled!==null||line.registered!==null))
       fail('LEGACY_PHONE_SCHEMA');
     return phone;
    }),
    history:await readSection('history',callLog),
    dns:await readSection('dns',async()=>{
        const res=await reader.cgi('dns');
     return readLegacyDns(requireBody(res));
      })};
    // Offered only when this firmware serves both its ClearLog() action and field.
   clearHistory=!!data.phone&&!!data.history&&cfg?.has('clearlog')===true&&await optional(async()=>
      hasNativeLegacyClearLog((await reader.page('/phones.htm')).body))===true;
   // Strict allowlist projection: never return arbitrary info CGI fields.
   data.device=await readSection('device',async()=>{
     const body=requireBody(await reader.cgi('info'));
     return readLegacyDevice(body);
   });
  }
  const phone=data.phone;
  phase(operation?'OPERATION_DONE':phone?'PHONE_READ':'PHONE_UNVERIFIED');
  // Optional diagnostic inspection (trial tooling); same GET-only reader.
  if(typeof inspect==='function'){
    try{await inspect(reader)}catch{}
    phase('INSPECTION_DONE');
  }
  const loggedOut=await closeSession();
  phase(loggedOut?'LOGGED_OUT':'LOGOUT_UNVERIFIED');
  const result={
   schema:2,family:'livebox-fibra-legacy',model:'Livebox Fibra (interfaz antigua)',
   authentication:'VERIFIED',readOnly:applyDispatched===0,configurationPosts:applyDispatched,
   reachable:true,loggedOut,attemptedAt,reads,...data,
   capabilities:{fieldCount:phone?.fieldCount??null,autodialRead:phone?.autodial.verified===true,
     lineRead:phone?.lines.some(l=>l.enabled!==null)===true,
    callHistory:!!data.history,dnsRead:!!data.dns,
    autodialWrite:phone?.autodial.verified===true&&await optional(async()=>legacyAutodialSnapshot(cfg))!==null,
    ringTest:!!phone&&cfg?.get('ring_test')?.value==='0',
     blocking:false,dnsWrite:false,clearHistory}
  };
  result.capturedAt=legacyCapturedAt(result);
  result.readStatus=legacyReadStatus(result);
  return result;
 }catch(error){
  const safe=new Set(['LEGACY_PROFILE_UNKNOWN','LEGACY_PROFILE_UNAVAILABLE',
   'LEGACY_LOGIN_FORM_UNKNOWN','LEGACY_LOGIN_UNVERIFIED',
   'LEGACY_READBACK_NOT_AUTHENTICATED','LEGACY_READBACK_UNAVAILABLE',
   'LEGACY_POST_NOT_ALLOWED','LEGACY_POST_NOT_DISPATCHED',
   'LEGACY_POST_NO_HTTP_RESPONSE','LEGACY_POST_HTTP_4XX',
   'LEGACY_POST_HTTP_5XX','LEGACY_POST_HTTP_UNEXPECTED',
   'LEGACY_PHONE_SCHEMA','CREDENTIAL_REQUIRED']);
  phase('FAILED');
  // Errors of an operation after verified login keep their own safe code.
  if(operating&&/^[A-Z][A-Z0-9_]{2,60}$/.test(error?.code||'')){
    await closeSession().catch(()=>{});
    fail(error.code);
  }
  // A dispatched login may have opened a session even if it was not verified.
  if(dispatched===1)await closeSession().catch(()=>{});
  fail(safe.has(error?.code)?error.code:'LEGACY_LOGIN_UNVERIFIED');
 }finally{
  password=null;
  await ctx?.close().catch(()=>{});
  await browser?.close().catch(()=>{});
 }
}

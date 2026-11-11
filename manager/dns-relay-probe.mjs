import {Resolver} from 'node:dns/promises';
import {isIP} from 'node:net';

const isIPv4=value=>typeof value==='string'&&isIP(value)===4;
const isIPv6=value=>typeof value==='string'&&isIP(value)===6;
const isDnsIdentityIp=value=>isIPv4(value)||isIPv6(value);
// The resolver's outward-facing address is evidence, not an ISP identity.
// Reject special-use/test/private IPv4 ranges without embedding a prefix
// observed on one subscriber connection or guessing the network provider.
const publicEgressIPv4=value=>{
 if(!isIPv4(value))return false;
 const [a,b,c]=value.split('.').map(Number);
 return !(a===0||a===10||a===127||a>=224||
   a===100&&b>=64&&b<=127||
   a===169&&b===254||
   a===172&&b>=16&&b<=31||
   a===192&&(b===168||b===0||b===88&&c===99)||
   a===198&&(b===18||b===19||b===51&&c===100)||
   a===203&&b===0&&c===113);
};
// TXT resolver-identity services may return the upstream's IPv6 egress even
// when the LAN client and the DNS query itself use IPv4. Accept only global
// unicast candidates, not link-local, ULA, loopback, IPv4-mapped or docs.
const publicEgressIPv6=value=>{
 if(!isIPv6(value))return false;
 const lower=value.toLowerCase();
 const first=Number.parseInt(lower.split(':')[0],16);
 if(!Number.isInteger(first)||first<0x2000||first>0x3fff)return false;
 // Documentation, Teredo/ORCHID and benchmark-only ranges are not evidence
 // of publicly routable recursive egress.
 if(first===0x2001){
   const second=Number.parseInt(lower.split(':')[1]||'0',16);
   if(second===0||second===0xdb8||second===2||
     second>=0x10&&second<=0x2f)return false;
 }
 return true;
};
const publicEgressIp=value=>publicEgressIPv4(value)||publicEgressIPv6(value);
// The firmware CA array is heterogeneous and may include credentials. Only
// publish field NAMES containing DNS-related tokens, never arbitrary values.
// A DNS field can still be a secret, e.g. dns_password: deny these by name.
const safeName=/^[a-z][a-z0-9_]{1,64}$/i;
const dnsName=/dns|resolver|resolv|forward|proxy|dnsmasq|relay/i;
const sensitiveName=/passw|passwd|pwd|secret|token|cookie|credential|auth|privatekey|accesskey|ssid|sipp?ass|serial|pin\d|wpa|wifi/i;
const MAX_NATIVE_NAMES=2048;
const nativeDnsFieldName=name=>typeof name==='string'&&safeName.test(name)&&
  dnsName.test(name)&&!sensitiveName.test(name);
const dnsCategory=name=>{
 if(/^wan_dns\d+$/i.test(name))return 'WAN_IPV4';
 if(/^(?:dns_proxy|dns_relay|dns_forward|resolv|resolver|dnsmasq|forward_dns)/i.test(name))
   return 'RELAY_CANDIDATES';
 if(/^ipv6_wan_dns/i.test(name))return 'WAN_IPV6';
 if(/^dslx_dns/i.test(name))return 'DSL_PROFILES';
 if(/^dns_(?:hostname|ip)\d+$/i.test(name))return 'LOCAL_HOST_RECORDS';
 return 'OTHER_DNS';
};
const categories=['WAN_IPV4','RELAY_CANDIDATES','WAN_IPV6',
  'DSL_PROFILES','LOCAL_HOST_RECORDS','OTHER_DNS'];
export function sanitizeNativeDnsNames(values){
 if(!Array.isArray(values)||values.length>4096)return [];
 const names=[...new Set(values.filter(nativeDnsFieldName))];
 names.sort((a,b)=>{
   const cat=categories.indexOf(dnsCategory(a))-categories.indexOf(dnsCategory(b));
   return cat||a.localeCompare(b,'en');
 });
 return names.slice(0,MAX_NATIVE_NAMES);
}
/** Categorized bounded inventory of safe DNS field *names* plus vetted IP /
 * flag observations from exact DSL-only identifiers. Unknown data is dropped.
 * Not a proof that an identifier controls the active GPON DNS proxy.
 */
export function describeNativeDnsInventory(input){
 if(!input||typeof input!=='object'||Array.isArray(input))return {
   status:'UNAVAILABLE',complete:false,totalConfigFields:null,
   matchingFields:null,capturedFields:0,groups:[],observedValues:[]};
 const names=sanitizeNativeDnsNames(input.names);
 const validCount=value=>Number.isSafeInteger(value)&&value>=0&&value<=100000;
 const total=validCount(input.totalConfigFields)?input.totalConfigFields:null;
 const matching=validCount(input.matchingFields)?input.matchingFields:null;
 const groups=categories.map(category=>{
   const entries=names.filter(x=>dnsCategory(x)===category);
   return {category,count:entries.length,names:entries};
 });
 const observed=[];
 if(Array.isArray(input.observedValues)&&input.observedValues.length<=16){
   for(const row of input.observedValues){
     if(!row||typeof row.name!=='string')continue;
     const name=row.name;
     if(!names.includes(name))continue;
     // Exactly four native WAN DNS fields are allowed to expose validated
     // IPv4 pairs. All other raw formats are redacted inside the browser.
     // This does not prove which WAN profile supplies the LAN DNS proxy.
     if(/^wan_dns[0-3]$/i.test(name)){
       if(row.kind==='ipv4_pair'&&isIPv4(row.primary)&&isIPv4(row.secondary))
         observed.push({name,kind:'ipv4_pair',primary:row.primary,secondary:row.secondary});
       else if(row.kind==='unrecognized')
         observed.push({name,kind:'unrecognized'});
     }else if(/^dslx_dns(?:1|2)_[0-3]$/i.test(name)&&row.kind==='ipv4'&&
       typeof row.value==='string'&&isIPv4(row.value))
       observed.push({name,kind:'ipv4',value:row.value});
     else if(/^dslx_dnsenable[0-3]$/i.test(name)&&row.kind==='flag'&&
       (row.value===true||row.value===false))
       observed.push({name,kind:'flag',value:row.value});
   }
 }
 const complete=matching!==null&&matching===names.length&&
   input.truncated!==true&&matching<=MAX_NATIVE_NAMES;
 return {status:'INSPECTED',complete,totalConfigFields:total,
   matchingFields:matching,capturedFields:names.length,
   missingFields:matching!==null?Math.max(0,matching-names.length):null,
   groups,observedValues:observed,
   scope:'Identifier names plus strictly validated WAN IPv4 pairs and selected DSL IPv4/flags; no private or arbitrary field values.'};
}
const isObject=v=>v!==null&&typeof v==='object'&&!Array.isArray(v);
function confirmed(result){
 return isObject(result)&&result.ok===true&&publicEgressIp(result.ip);
}
async function query({createResolver,server,host,kind}){
 let resolver;
 try {
  resolver=createResolver();
  resolver.setServers([server]);
  const value=kind==='A'?
    await resolver.resolve4(host):
    await resolver.resolveTxt(host);
  const first=kind==='A'?(Array.isArray(value)?value.find(isIPv4):null):
    (Array.isArray(value)?value.flat().find(isDnsIdentityIp):null);
  if(!isDnsIdentityIp(first))return {ok:false,ip:null};
  return {ok:true,ip:first};
 }catch{return {ok:false,ip:null};}
 finally{try{resolver?.cancel?.();}catch{}}
}
/**
 * Read-only upstream fingerprints of two public diagnosis names.
 * The router's DNS relay and Cloudflare are queried directly over
 * their respective UDP/53 interfaces; the OS resolver is never changed.
 * No router CGI POST, HTTP sessions, credentials or user-supplied
 * DNS names are involved. Unknown responses fail to an indeterminate
 * classification instead of fabricating provider identities.
 */
export async function probeDnsRelay({
 routerIp='192.168.1.1',
 createResolver=()=>new Resolver({timeout:3200,tries:1}),
 clock=()=>new Date().toISOString()
}={}){
 if(!isIPv4(routerIp)||routerIp==='0.0.0.0'||routerIp==='255.255.255.255')
   throw Object.assign(Error('DNS_RELAY_UNAVAILABLE'),{code:'DNS_RELAY_UNAVAILABLE'});
 if(typeof createResolver!=='function'||typeof clock!=='function')
   throw Object.assign(Error('DNS_RELAY_UNAVAILABLE'),{code:'DNS_RELAY_UNAVAILABLE'});
 const [relayAkamai,relayGoogle,cloudflareAkamai,cloudflareGoogle]=await Promise.all([
  query({createResolver,server:routerIp,host:'whoami.akamai.net',kind:'A'}),
  query({createResolver,server:routerIp,host:'o-o.myaddr.l.google.com',kind:'TXT'}),
  query({createResolver,server:'1.1.1.1',host:'whoami.akamai.net',kind:'A'}),
  query({createResolver,server:'1.0.0.1',host:'o-o.myaddr.l.google.com',kind:'TXT'})
 ]);
 const observedEgress=confirmed(relayAkamai)&&confirmed(relayGoogle);
 return {
  schema:1,checkedAt:clock(),routerIp,
  classification:observedEgress?'RECURSIVE_EGRESS_OBSERVED':'INDETERMINATE',
  relay:{akamai:relayAkamai,google:relayGoogle},
  cloudflareReference:{akamai:cloudflareAkamai,google:cloudflareGoogle},
  nativeDnsConfigPosts:0,
  diagnosisServices:['whoami.akamai.net','o-o.myaddr.l.google.com'],
  note:observedEgress?
   'Se han observado IP públicas de salida de dos consultas del proxy del router. No permiten atribuir un ISP ni deducir qué DNS WAN utiliza.':
   'No se puede acreditar el resolvedor efectivo con estas consultas; no se modifica el router.'
 };
}

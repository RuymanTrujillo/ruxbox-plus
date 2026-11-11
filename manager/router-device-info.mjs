import {isIP} from 'node:net';
import {lookupService,lookup} from 'node:dns/promises';

// Two exact CGI scripts loaded by Livebox 6's support_information.htm.
// Parse only selected scalar assignments. Never execute CGI JavaScript.
// Never export serial numbers, MAC addresses, tokens or credentials.
export const DEVICE_INFO_SOURCES=Object.freeze([
  '/cgi/cgi_router_status.js','/cgi/cgi_info.js'
]);
function schemaFail(){throw Object.assign(new Error('DEVICE_INFO_SCHEMA'),{code:'DEVICE_INFO_SCHEMA'});}
const maxBytes=16*1024;
const safeText=(value,max=100)=>{
  if(typeof value!=='string'||value.length>max||value.length===0||
    /[\x00-\x1f\x7f<>]/u.test(value))return null;
  return value;
};
const identifier=(value,max=70)=>
  safeText(value,max)&&/^[A-Za-z0-9._-]{2,70}$/u.test(value)?value:null;

function readScalars(text){
  if(typeof text!=='string'||Buffer.byteLength(text,'utf8')>maxBytes)
    schemaFail();
  const fields=new Map();
  // A complete assignment on its own line; escaped strings are not
  // interpreted and non-scalar statements are deliberately ignored.
  const re=/^\s*var\s+([a-z][a-z0-9_]*)\s*=\s*(["'])([^'"\\\r\n]{0,300})\2\s*;\s*$/gmu;
  for(const line of text.split(/\r?\n/u)){
    re.lastIndex=0;
    const match=re.exec(line);
    if(!match)continue;
    const name=match[1];
    if(fields.has(name))schemaFail();
    fields.set(name,match[3]);
  }
  return fields;
}

export function parseRouterDeviceInfo({routerStatus,info,at=new Date().toISOString()}={}){
  const status=readScalars(routerStatus),system=readScalars(info);
  const hardwareModel=identifier(status.get('hardware_model'));
  const firmwareVersion=identifier(status.get('firmware_version'));
  if(!hardwareModel||!firmwareVersion)schemaFail();
  const firmwareBuild=identifier(status.get('firmware_sub_version'))||null;
  const hardwareVersion=identifier(status.get('hardware_version'))||null;
  const bootloaderVersion=identifier(status.get('boot_code_version'))||null;
  const manufacturer=safeText(system.get('manufacturer'),70);
  const routerIsp=safeText(system.get('isp'),110);
  const wanMode=identifier(system.get('wan_mode'),30);
  const wanCandidate=system.get('defroute_wan_ip');
  const wanIPv4=typeof wanCandidate==='string'&&isIP(wanCandidate)===4?wanCandidate:null;
  const uptimeStr=status.get('uptime');
  const uptimeSeconds=typeof uptimeStr==='string'&&/^\d+(?:\.\d+)?$/u.test(uptimeStr)&&
    Number.isSafeInteger(Math.floor(Number(uptimeStr)))&&Number(uptimeStr)<1e10?
    Math.floor(Number(uptimeStr)):null;
  // Mirror the vendor's own support_information.htm construction exactly
  // when this particular ARLT Livebox model is identified.
  const firmwareDisplay=hardwareModel==='ARLTFIBRA6'?
    (firmwareVersion.charAt(1)==='3'?'ARPLUS6-sp-':'ARFIBRA6-sp-')+firmwareVersion:
    firmwareVersion;
  return {
    hardwareModel,firmwareVersion,firmwareDisplay,firmwareBuild,
    hardwareVersion,bootloaderVersion,manufacturer,routerIsp,
    wanMode,wanIPv4,uptimeSeconds,
    source:'livebox-native-system-cgi',fetchedAt:at
  };
}

export async function readLocalRouterHostname(ip,{
  lookupServiceFn=lookupService,lookupFn=lookup,timeoutMs=9000
}={}){
  if(typeof ip!=='string'||isIP(ip)!==4||typeof lookupServiceFn!=='function'||
    typeof lookupFn!=='function'||!Number.isFinite(timeoutMs)||timeoutMs<100||timeoutMs>12000)
    throw Error('INVALID_LOCAL_NAME_REQUEST');
  const expiry=Date.now()+timeoutMs;
  const withDeadline=promise=>{
    const remaining=expiry-Date.now();
    if(remaining<=0)throw Error('LOCAL_DNS_TIMEOUT');
    let timer;
    return Promise.race([
      promise,new Promise((_,reject)=>{
        timer=setTimeout(()=>reject(Error('LOCAL_DNS_TIMEOUT')),remaining);
        timer.unref?.();
      })
    ]).finally(()=>clearTimeout(timer));
  };
  try{
    const result=await withDeadline(Promise.resolve().then(()=>lookupServiceFn(ip,80)));
    const hostname=result?.hostname;
    if(typeof hostname!=='string'||hostname.length>253||
      !/^[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?$/iu.test(hostname)||
      isIP(hostname))return null;
    // A local reverse answer alone can be stale. A forward A record must
    // map the same name to the configured router IPv4 address.
    const forward=await withDeadline(Promise.resolve().then(()=>lookupFn(hostname,{all:true})));
    if(!Array.isArray(forward)||!forward.some(x=>x?.address===ip))return null;
    return {hostname,source:'local-dns-ptr-forward-confirmed'};
  }catch{return null;}
}


export function projectRouterDeviceInfo(value){
  if(!value||typeof value!=='object'||Array.isArray(value)||
    value.source!=='livebox-native-system-cgi'||
    !identifier(value.hardwareModel)||!identifier(value.firmwareVersion)||
    !safeText(value.firmwareDisplay,120)||
    typeof value.fetchedAt!=='string'||
    !Number.isFinite(Date.parse(value.fetchedAt)))schemaFail();
  return {
    hardwareModel:value.hardwareModel,
    firmwareVersion:value.firmwareVersion,
    firmwareDisplay:value.firmwareDisplay,
    firmwareBuild:identifier(value.firmwareBuild)||null,
    hardwareVersion:identifier(value.hardwareVersion)||null,
    bootloaderVersion:identifier(value.bootloaderVersion)||null,
    manufacturer:safeText(value.manufacturer,70),
    routerIsp:safeText(value.routerIsp,110),
    wanMode:identifier(value.wanMode,30)||null,
    wanIPv4:typeof value.wanIPv4==='string'&&isIP(value.wanIPv4)===4?value.wanIPv4:null,
    uptimeSeconds:Number.isSafeInteger(value.uptimeSeconds)&&value.uptimeSeconds>=0?
      value.uptimeSeconds:null,
    source:'livebox-native-system-cgi',
    fetchedAt:value.fetchedAt
  };
}

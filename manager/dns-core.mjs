import {createHash} from 'node:crypto';
const fail=(code)=>{throw Object.assign(new Error(code),{code});};
const ipv4Value=(text,{allowZero=false}={})=>{
  if(typeof text!=='string'||!/^(?:\d{1,3}\.){3}\d{1,3}$/.test(text))return false;
  const octets=text.split('.');
  if(octets.some(x=>(x.length>1&&x.startsWith('0'))||Number(x)>255))return false;
  const [first,second]=octets.map(Number);
  if(!allowZero&&text==='0.0.0.0')return false;
  if(first===127||first===0&&text!=='0.0.0.0'||
    first===169&&second===254||first>=224)return false;
  return true;
};
export function validateDnsPair(value){
  if(!value||typeof value!=='object'||Array.isArray(value)||
    Object.keys(value).sort().join(',')!=='primary,secondary'||
    !ipv4Value(value.primary)||!ipv4Value(value.secondary)||
    value.primary===value.secondary)fail('DNS_INVALID');
  return {primary:value.primary,secondary:value.secondary};
}
export function parseDnsValue(raw){
  if(typeof raw!=='string'||raw.length>128||/[\r\n\0]/.test(raw))
    fail('DNS_SCHEMA');
  const normalized=raw.trim();
  // Unconfigured/automatic WAN DNS may have an empty scalar or one
  // zero address. These are readable, but never valid proposed DNS.
  if(normalized===''||normalized==='0.0.0.0')
    return {primary:'0.0.0.0',secondary:'0.0.0.0',automatic:true};
  const parts=normalized.split(/\s+/);
  if(parts.length!==2||parts.some(x=>!ipv4Value(x,{allowZero:true})))fail('DNS_SCHEMA');
  return {primary:parts[0],secondary:parts[1],automatic:parts.every(x=>x==='0.0.0.0')};
}
export const dnsRevision=({raw,fieldId})=>{
  if(typeof raw!=='string'||!Number.isSafeInteger(fieldId)||fieldId<=0)
    fail('DNS_SCHEMA');
  return createHash('sha256').update(JSON.stringify(['wan_dns0',fieldId,raw])).digest('hex');
};
export function validateDnsNativeForm(form,expected){
  if(!form||form.command!=='DNS_CONF'||form.action!=='apply_abstract.cgi'||
    String(form.method).toUpperCase()!=='POST'||form.integrity?.actionEncoded!==true||
    form.integrity?.dnsValueEncoded!==true||
    form.integrity?.onlyDnsChanged!==true||
    !Array.isArray(form.inputs)||form.inputs.length!==5)fail('DNS_FORM_MISMATCH');
  const id=String(expected?.fieldId);
  if(!/^[0-9]{1,20}$/.test(id)||id==='0')fail('DNS_FORM_MISMATCH');
  const names=['action','httoken','submit_button','805443298771',id];
  if(new Set(form.inputs.map(x=>x?.name)).size!==5||
    names.some(name=>form.inputs.filter(x=>x.name===name).length!==1)||
    form.inputs.some(x=>typeof x.value!=='string'||!x.value||x.value.length>600)||
    form.inputs.find(x=>x.name==='submit_button')?.value!=='advanced_network_dns.htm'||
    form.inputs.some(x=>x.name==='action_params'||x.name.includes('*')))
    fail('DNS_FORM_MISMATCH');
  return true;
}

// Livebox WAN DNS mode (automatic vs static) for the default-route profile.
// The firmware keeps three CA rows per profile: dslx_dnsenable<r> ("1" auto,
// "0" static) and dslx_dns1_<r>/dslx_dns2_<r> (static IPv4 or empty).
// wan_dns<r> (lease/DNS_CONF value) is never written by a mode change.
const DNS_MODE_FORM_BASE=['action','httoken','submit_button','805443298771'];
const emptyOrIpv4=v=>v===''||ipv4Value(v);
export function validateDnsModeTarget(value){
  if(!value||typeof value!=='object'||Array.isArray(value))fail('DNS_INVALID');
  const keys=Object.keys(value).sort().join(',');
  if(value.automatic===true&&keys==='automatic')return {automatic:true};
  if(value.automatic===false&&keys==='automatic,primary,secondary')
    return {automatic:false,...validateDnsPair({primary:value.primary,secondary:value.secondary})};
  fail('DNS_INVALID');
}
export function parseDnsMode(observed,wan){
  if(!observed||observed.command!=='ui_dns'||observed.encoder!==true)fail('DNS_COMMAND_MISSING');
  if(typeof observed.route!=='string'||!/^[0-3]$/.test(observed.route))fail('DNS_SCHEMA');
  const r=observed.route;
  const names=['dslx_dnsenable'+r,'dslx_dns1_'+r,'dslx_dns2_'+r];
  const rows=observed.rows;
  if(!Array.isArray(rows)||rows.length!==3)fail('DNS_FIELD_MISSING');
  rows.forEach((row,i)=>{
    if(!row||row.name!==names[i]||!Number.isSafeInteger(row.id)||row.id<=0)fail('DNS_FIELD_MISSING');
    if(row.encrypted!==false||typeof row.value!=='string')fail('DNS_SCHEMA');
  });
  if(new Set(rows.map(x=>x.id)).size!==3||rows.some(x=>x.id===wan?.fieldId))fail('DNS_SCHEMA');
  const [enable,dns1,dns2]=rows.map(x=>x.value);
  if(!['0','1'].includes(enable)||!emptyOrIpv4(dns1)||!emptyOrIpv4(dns2))fail('DNS_SCHEMA');
  if(typeof wan?.raw!=='string'||!Number.isSafeInteger(wan?.fieldId))fail('DNS_SCHEMA');
  const plain=rows.map(({name,id,value})=>({name,id,value}));
  return {route:r,automatic:enable==='1',primary:dns1,secondary:dns2,rows:plain,
    revision:createHash('sha256').update(JSON.stringify(['dns-mode',r,plain,wan.fieldId,wan.raw])).digest('hex')};
}
export function dnsModeChanges(before,target){
  const t=validateDnsModeTarget(target);
  const wanted=t.automatic?['1','','']:['0',t.primary,t.secondary];
  return before.rows.map((row,i)=>({name:row.name,id:row.id,value:wanted[i]}))
    .filter((c,i)=>c.value!==before.rows[i].value);
}
export function validateDnsModeForm(form,{changes}){
  if(!Array.isArray(changes)||changes.length<1||changes.length>3)fail('DNS_FORM_MISMATCH');
  if(!form||form.command!=='ui_dns'||form.action!=='apply_abstract.cgi'||
    String(form.method).toUpperCase()!=='POST'||form.integrity?.actionEncoded!==true||
    form.integrity?.valuesEncoded!==true||!Array.isArray(form.integrity?.changed)||
    [...form.integrity.changed].sort().join()!==changes.map(c=>c.name).sort().join()||
    !Array.isArray(form.inputs)||form.inputs.length!==DNS_MODE_FORM_BASE.length+changes.length)
    fail('DNS_FORM_MISMATCH');
  const expected=[...DNS_MODE_FORM_BASE,...changes.map(c=>String(c.id))];
  if(new Set(form.inputs.map(x=>x?.name)).size!==expected.length||
    expected.some(name=>form.inputs.filter(x=>x.name===name).length!==1)||
    form.inputs.some(x=>typeof x.value!=='string'||x.value.length>600)||
    // Only a static address being cleared (automatic mode) may encode to ''.
    form.inputs.some(x=>!x.value&&!changes.some(c=>String(c.id)===x.name&&c.value===''))||
    form.inputs.find(x=>x.name==='submit_button')?.value!=='advanced_network_dns.htm')
    fail('DNS_FORM_MISMATCH');
  return true;
}

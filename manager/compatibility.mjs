import {createHash} from 'node:crypto';
import {validateState,EXPECTED_BLOCK_NAMES} from './core.mjs';

// Independent, read-only firmware-shape inspector. Never executes returned CGI,
// rewrites router fields or authorizes a native POST.
export const COMPAT_PROFILE = 'livebox6-observed-2026-10-27';
const sha = value => createHash('sha256').update(value).digest('hex');
const fail = code => {throw Object.assign(new Error(code),{code});};
const phoneNames = new Set();
for(const [prefix,count] of [
  ['extacc_user_id_',10],['intacc_display_name_',17],
  ['intacc_out_call_mapping_',17],['extacc_in_mapping_',10],
  ['phone_hotline_number_',8],['phone_hotline_timeout_',8],
  ['phone_hotline_enable_',8]
]) for(let i=0;i<count;i++)phoneNames.add(prefix+i);
if(phoneNames.size!==78)throw Error('INVALID_COMPAT_PROFILE');

export function readNativeCfgRows(body,{maxRows=340}={}){
  if(typeof body!=='string'||Buffer.byteLength(body,'utf8')>256*1024)fail('COMPAT_SCHEMA');
  const quoted = '"((?:\\\\.|[^"\\\\])*)"';
  const rx = new RegExp('addCfg\\(\\s*'+quoted+'\\s*,\\s*'+quoted+'\\s*,\\s*'+quoted+'\\s*\\)','g');
  const found=[...body.matchAll(rx)];
  if(!found.length||found.length>maxRows||(body.match(/\baddCfg\s*\(/g)||[]).length!==found.length)
    fail('COMPAT_SCHEMA');
  let rows;
  try {
    rows=found.map(v=>({name:JSON.parse('"'+v[1]+'"'),
      id:JSON.parse('"'+v[2]+'"'),value:JSON.parse('"'+v[3]+'"')}));
  }catch{fail('COMPAT_SCHEMA');}
  const names=new Set(),ids=new Set();
  for(const row of rows){
    if(!/^[a-z][a-z0-9_]{0,79}$/.test(row.name)||!/^\d{12}$/.test(row.id)||
      row.value.length>4096||names.has(row.name)||ids.has(row.id))fail('COMPAT_SCHEMA');
    names.add(row.name);ids.add(row.id);
  }
  return rows;
}

export function inspectBlockCgi(body){
  const input=readNativeCfgRows(body,{maxRows:306});
  const wanted=new Set(EXPECTED_BLOCK_NAMES);
  const core=input.filter(row=>wanted.has(row.name));
  if(core.length!==EXPECTED_BLOCK_NAMES.length)fail('COMPAT_REQUIRED_FIELD_MISSING');
  const state=validateState(core);
  // Stable firmware field names define compatibility. Native 12-digit IDs are
  // learned per device from authenticated CGI and validated as unique. Their
  // identity remains part of each snapshot revision and post-write delta,
  // so a changed ID between planning and dispatch fails closed.
  if(state.schema.some(({name},i)=>name!==EXPECTED_BLOCK_NAMES[i]))
    fail('COMPAT_SCHEMA');
  const extraFields=input.length-core.length;
  const exact=extraFields===0&&input.length===EXPECTED_BLOCK_NAMES.length;
  return {rows:state.rows,exact,extraFields,
    fingerprint:sha(JSON.stringify(state.schema)),mode:exact?'known':'read-only'};
}

export function inspectPhoneCgi(body) {
  const fields=readNativeCfgRows(body,{maxRows:126})
    .map(({name,id,value})=>[name,id,value]).sort((a,b)=>a[0].localeCompare(b[0]));
  const names=fields.map(x=>x[0]);
  const exact=fields.length===78&&names.every(name=>phoneNames.has(name))&&
    new Set(names).size===78;
  // Content hash still contributes to revision verification; never sent to UI.
  return {fields,exact,count:fields.length,digest:sha(JSON.stringify(fields)),
    fingerprint:sha(JSON.stringify(fields.map(x=>[x[0],x[1]]))),
    mode:exact?'known':'read-only'};
}

export function composeCompatibility({block,phone,commands}){
  if(!block||!phone||!commands)fail('COMPAT_SCHEMA');
  const dataSafe=block.exact===true&&phone.exact===true;
  const add=dataSafe&&commands.add===true;
  const remove=dataSafe&&commands.delete===true;
  const clear=dataSafe&&commands.clear===true;
  const reasons=[];
  if(!block.exact)reasons.push(block.extraFields?
    'BLOCK_SCHEMA_EXTENDED':'BLOCK_FORMAT_CHANGED');
  if(!phone.exact)reasons.push('PHONE_SCHEMA_CHANGED');
  if(!commands.add)reasons.push('NATIVE_ADD_UNAVAILABLE');
  if(!commands.delete)reasons.push('NATIVE_DELETE_UNAVAILABLE');
  if(!commands.clear)reasons.push('NATIVE_CLEAR_UNAVAILABLE');
  // Model label comes from the observed interface profile, not firmware version.
  // No trustworthy version was present in the archived native CGI/UI.
  return {profile:COMPAT_PROFILE,model:'Interfaz Livebox 6 (perfil observado)',
    firmware:null,confidence:'interfaz-inferida',
    status:reasons.length===0?'compatible':'limited',
    features:{callHistory:'on-demand',blockList:true,add,delete:remove,clearHistory:clear},
    reasons,shape:{blockingFingerprint:block.fingerprint,
      telephoneFingerprint:phone.fingerprint||null,
      extraBlockingFields:block.extraFields||0,
      telephoneFieldCount:phone.count},
    safeWrites:dataSafe};
}

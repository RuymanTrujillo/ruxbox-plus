import {createHash} from 'node:crypto';

const FAIL=(code)=>{throw Object.assign(new Error(code),{code});};
const GROUPS=Object.freeze({
 enable:['phone_hotline_enable_0','phone_hotline_enable_1'],
 number:['phone_hotline_number_0','phone_hotline_number_1'],
 timeout:['phone_hotline_timeout_0','phone_hotline_timeout_1']
});
const REQUIRED=Object.values(GROUPS).flat();
const digitsAndPhone= /^[+*#0-9-]{1,32}$/;
const sha=string=>createHash('sha256').update(string).digest('hex');

export function parseAutodialFields(fields){
 if(!Array.isArray(fields))FAIL('AUTODIAL_SCHEMA');
 const byName=new Map(fields.filter(x=>Array.isArray(x)&&x.length>=3).map(x=>[x[0],x]));
 const rows=REQUIRED.map(name=>{
   const item=byName.get(name);
   if(!item||item[0]!==name||!Number.isSafeInteger(Number(item[1]))||Number(item[1])<=0||
     typeof item[2]!=='string')FAIL('AUTODIAL_SCHEMA');
   return {name,id:Number(item[1]),value:item[2]};
 });
 if(new Set(rows.map(x=>x.id)).size!==6)FAIL('AUTODIAL_SCHEMA');
 const get=name=>rows.find(x=>x.name===name).value;
 const enabled=get('phone_hotline_enable_0');
 const destination=get('phone_hotline_number_0');
 const seconds=get('phone_hotline_timeout_0');
 if(!/^[01]$/.test(enabled)||
    (destination!==''&&!digitsAndPhone.test(destination))||
    !/^(?:10|[1-9])$/.test(seconds)||
    get('phone_hotline_enable_1')!==enabled||
    get('phone_hotline_number_1')!==destination||
    get('phone_hotline_timeout_1')!==seconds)FAIL('AUTODIAL_SCHEMA');
 return Object.freeze({
   enabled:enabled==='1',number:destination,seconds:Number(seconds),
   revision:sha(JSON.stringify(rows.map(x=>[x.name,x.id,x.value]))),
   rows
 });
}
export function validateAutodialUpdate(type,value){
 if(type==='enable'&&typeof value==='boolean')return {type,value:value?'1':'0'};
 if(type==='number'&&typeof value==='string'&&digitsAndPhone.test(value))return {type,value};
 if(type==='timeout'&&Number.isInteger(value)&&value>=1&&value<=10)return {type,value:String(value)};
 FAIL('AUTODIAL_INVALID');
}
export function autoDialChanges(before,type,value){
 if(!before?.rows||typeof before.revision!=='string')FAIL('AUTODIAL_SCHEMA');
 const action=validateAutodialUpdate(type,value);
 const names=GROUPS[type];
 const rows=before.rows.filter(x=>names.includes(x.name));
 if(rows.length!==2)FAIL('AUTODIAL_SCHEMA');
 if(rows.every(x=>x.value===action.value))FAIL('AUTODIAL_UNCHANGED');
 return {type,desired:action.value,rows:rows.map(x=>({...x,newValue:action.value})),
   previous:type==='enable'?(before.enabled?'1':'0'):type==='number'?before.number:String(before.seconds)};
}
export function publicAutodial(before){
 return {enabled:before.enabled,number:before.number,seconds:before.seconds,
   revision:before.revision,capturedAt:new Date().toISOString()};
}
export function assertNativeAutodialForm(form,before,change){
 if(form?.command!=='ui_sipp_hotline_osp'||form?.method?.toUpperCase()!=='POST'||
   form.action!=='apply_abstract.cgi'||!form.integrity?.actionEncoded||
   !form.integrity?.valuesEncoded||!form.integrity?.onlyExpectedChanged||
   !Array.isArray(form.inputs)||form.inputs.length!==6)FAIL('AUTODIAL_FORM_MISMATCH');
 const expected=['action','httoken','submit_button','805443298771',...change.rows.map(x=>String(x.id))];
 if(new Set(form.inputs.map(x=>x.name)).size!==6||
   expected.some(name=>form.inputs.filter(x=>x.name===name).length!==1)||
   form.inputs.some(x=>typeof x.value!=='string'||!x.value)||
   form.inputs.find(x=>x.name==='submit_button')?.value!=='phones.htm')
   FAIL('AUTODIAL_FORM_MISMATCH');
 return true;
}

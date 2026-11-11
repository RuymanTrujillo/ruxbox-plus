import {validateState} from './core.mjs';

// Pure, independently tested contract for the firmware-generated forms.
// The router's do_encode() is deterministic for a given native session.
// Its encoded action and parameter are checked inside that same session
// before the one permitted configuration POST can be reserved.
const COMMANDS=Object.freeze({
  add:'ui_sipp_no_blk_add_incoming',
  delete:'ui_sipp_no_blk_del_incoming',
});
function fail(code){throw Object.assign(new Error(code),{code});}

// Ring test reproduces the firmware-declared one-shot VoIP form only.
// It must contain no telephone configuration fields or arbitrary parameters.
export function assertNativeRingTestForm(form) {
  if(form?.command!=='ui_voip_ring_test_osp'||form.method?.toUpperCase()!=='POST'||
     form.action!=='apply_abstract.cgi'||form.integrity?.actionEncoded!==true||
     !Array.isArray(form.inputs)||form.inputs.length!==4)fail('FORM_MISMATCH');
  const names=['action','httoken','submit_button','805443298771'];
  if(new Set(form.inputs.map(x=>x.name)).size!==4||
     names.some(name=>form.inputs.filter(x=>x.name===name).length!==1)||
     form.inputs.some(x=>typeof x.value!=='string'||!x.value)||
     form.inputs.find(x=>x.name==='submit_button').value!=='phones.htm')
    fail('FORM_MISMATCH');
  return true;
}

export function assertNativeClearLogForm(form) {
  if (form?.command !== 'ui_call_log_del_all' || form.method?.toUpperCase() !== 'POST' ||
      form.action !== 'apply_abstract.cgi' ||
      form.integrity?.actionEncoded !== true ||
      !Array.isArray(form.inputs) || form.inputs.length !== 4) fail('FORM_MISMATCH');
  const names=['action','httoken','submit_button','805443298771'];
  if(new Set(form.inputs.map(x=>x.name)).size!==names.length||
     names.some(name=>form.inputs.filter(x=>x.name===name).length!==1)||
     form.inputs.some(x=>typeof x.value!=='string'||!x.value)||
     form.inputs.find(x=>x.name==='submit_button').value!=='phones.htm')
    fail('FORM_MISMATCH');
  return true;
}

export function assertNativeForm(form,rows,type) {
  validateState(rows);
  if(!Object.hasOwn(COMMANDS,type)||form?.command!==COMMANDS[type]||
     form.method?.toUpperCase()!=='POST'||form.action!=='apply_abstract.cgi'||
     form.integrity?.actionEncoded!==true||form.integrity?.parameterEncoded!==true||
     !Array.isArray(form.inputs)||form.inputs.length!==5)fail('FORM_MISMATCH');
  const names=['action','httoken','submit_button','action_params','805443298771'];
  if(new Set(form.inputs.map(x=>x.name)).size!==names.length||
     names.some(name=>form.inputs.filter(x=>x.name===name).length!==1)||
     form.inputs.some(x=>typeof x.value!=='string'||x.value==='')||
     form.inputs.find(x=>x.name==='submit_button').value!=='phones.htm')fail('FORM_MISMATCH');
  const ids=new Set(rows.map(x=>x.id));
  if(form.inputs.some(x=>ids.has(x.name.replace(/\*$/,''))))
    fail('FORM_CONFIGURATION_FIELDS');
  return true;
}

// Strict, non-executing parser for the observed call-log CGI.
import {createHash,createHmac} from 'node:crypto';
import {routerDateTimeParts,callDateKey} from './public/history-view.mjs';

// Keep the original 128 KiB transport budget. Removing the independent 500/100
// row caps makes every validated row accessible without increasing that budget.
const MAX_JS_BYTES = 131072;
const EMPTY_ARRAY_BYTES = Buffer.byteLength('var voip_call_logs=[];');
const MIN_ENTRY_BYTES = Buffer.byteLength(JSON.stringify('IN,01.01.0001 00:00,0s,x,x'))+1;
const MAX_RECORDS = Math.floor((MAX_JS_BYTES-EMPTY_ARRAY_BYTES+1)/MIN_ENTRY_BYTES);
export const CALL_HISTORY_LIMITS=Object.freeze({maxJavascriptBytes:MAX_JS_BYTES,maxRecords:MAX_RECORDS});
const DURATION = /^(?:[0-9]+h)?(?:[0-9]+m)?[0-9]+s$/;
const ASCII_CALLER = /^[\x20-\x7e]{1,64}$/;
const DIGITS = /^[0-9]{1,32}$/;
function bad(reason,code='CALL_LOG_SCHEMA') {throw Object.assign(new Error(reason), {code});}
const validDateTime=value=>routerDateTimeParts(value)?.separator==='.';
function validFields(type,dateTime,duration,source,destination) {
  return ['IN','OUT','MISS'].includes(type) && validDateTime(dateTime) &&
    typeof duration==='string' && DURATION.test(duration) &&
    typeof source==='string' && ASCII_CALLER.test(source) && source===source.trim() &&
    typeof destination==='string' && ASCII_CALLER.test(destination) && destination===destination.trim();
}

export function parseCallLogJavascript(body) {
  if (typeof body !== 'string' || !body.length) bad('INVALID_CALL_LOG_BYTES');
  if (Buffer.byteLength(body,'utf8')>MAX_JS_BYTES) bad('CALL_LOG_TOO_LARGE','CALL_LOG_TOO_LARGE');
  const declaration=/\bvar\s+voip_call_logs\s*=\s*\[/g;
  const start=declaration.exec(body);
  if (!start) bad('CALL_LOG_DECLARATION_MISSING');
  let cursor=start.index+start[0].length;
  const whitespace=()=>{while(cursor<body.length && /\s/.test(body[cursor]))cursor++;};
  const items=[];
  whitespace();
  while(body[cursor]!==']') {
    if(body[cursor]!=='"') bad('CALL_LOG_ENTRY_UNRECOGNIZED');
    const first=cursor++;
    let closed=false;
    for(;cursor<body.length;cursor++) {
      if(body[cursor]==='\\') cursor++;
      else if(body[cursor]==='"') {cursor++;closed=true;break;}
    }
    if(!closed) bad('CALL_LOG_LITERAL_INVALID');
    let value;
    try {value=JSON.parse(body.slice(first,cursor));} catch {bad('CALL_LOG_LITERAL_INVALID');}
    if (typeof value !== 'string') bad('CALL_LOG_LITERAL_TYPE');
    const fields = value.split(',');
    if (fields.length !== 5) bad('CALL_LOG_FIELD_COUNT');
    const [type, dateTime, duration, source, destination] = fields;
    if(!validFields(type,dateTime,duration,source,destination)) bad('CALL_LOG_FIELD_INVALID');
    items.push({type, dateTime, duration, source, destination,
      selectable: type !== 'OUT' && DIGITS.test(source)});
    whitespace();
    if(body[cursor]===',') {cursor++;whitespace();}
    else if(body[cursor]!==']') bad('CALL_LOG_SEPARATOR_MISSING');
  }
  cursor++;whitespace();
  if(body[cursor]!==';') bad('CALL_LOG_TERMINATION_MISSING');
  // A valid but empty router log is not a parse error.
  return items;
}

export function validateCallHistory(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value) ||
      Object.keys(value).some(key => !['capturedAt','total','calls','truncated'].includes(key)) ||
      typeof value.capturedAt !== 'string' || !Number.isFinite(Date.parse(value.capturedAt)) ||
      !Number.isInteger(value.total) || value.total < 0 || value.total > MAX_RECORDS ||
      !Array.isArray(value.calls) || value.calls.length > MAX_RECORDS ||
      value.calls.length > value.total ||
      (value.truncated!==undefined && (typeof value.truncated!=='boolean' ||
        value.truncated!==(value.total>value.calls.length)))) bad('CALL_LOG_ENVELOPE');
  let encodedBytes=EMPTY_ARRAY_BYTES;
  for (const item of value.calls) {
    if (!item || typeof item !== 'object' || Array.isArray(item) ||
        Object.keys(item).some(key=>!['type','dateTime','duration','source','destination','selectable'].includes(key)) ||
        !validFields(item.type,item.dateTime,item.duration,item.source,item.destination) ||
        typeof item.selectable !== 'boolean' ||
        item.selectable !== (item.type !== 'OUT' && DIGITS.test(item.source))) bad('CALL_LOG_ITEM');
    encodedBytes+=Buffer.byteLength(JSON.stringify([item.type,item.dateTime,item.duration,item.source,item.destination].join(',')))+1;
    if(encodedBytes-1>MAX_JS_BYTES) bad('CALL_LOG_TOO_LARGE','CALL_LOG_TOO_LARGE');
  }
  return {...value,truncated:value.total>value.calls.length};
}
// SHA-256 of a validated list, so a stored plan never keeps phone numbers.
export const callHistoryRevision=log=>createHash('sha256').update(JSON.stringify([log.total,
  log.calls.map(c=>[c.type,c.dateTime,c.duration,c.source,c.destination])])).digest('hex');
// v2 receipts use the original 64-bit public mark and must remain readable.
// New v3 receipts use an attempt-specific 256-bit HMAC including both numbers.
// The secret is kept in a separate private file; journal JSON contains no numbers
// or HMAC key. Two distinct numbers with the same minute/type/duration no longer
// collapse into one mark. Identical full visible records are still indistinguishable.
export function callMarks(log,{key=null}={}){
 if(key!==null&&(!Buffer.isBuffer(key)||key.length!==32))bad('CALL_MARK_KEY');
 return log.calls.map(c=>key===null?
   createHash('sha256').update(JSON.stringify([c.type,c.dateTime,c.duration]))
     .digest('hex').slice(0,16):
   createHmac('sha256',key).update(JSON.stringify([
     c.type,c.dateTime,c.duration,c.source,c.destination])).digest('hex'));
}

// Fixed meaning of each reconciliation outcome; anything else stays in review.
export const CLEAR_RESOLUTIONS=Object.freeze({
  notSent:{status:'failed',configurationPosts:0},
  notApplied:{status:'failed',configurationPosts:null},
  cleared:{status:'succeeded',configurationPosts:1}});
/**
 * Decide a pending history clear from its journal and an independent read.
 * Pure: never reads or writes. The native clear is all-or-nothing, so the
 * confirmed calls are either all still listed (not applied) or all gone.
 * dispatch: 'absent' | 'invalid' | {settingsRevision}
 */
export function classifyClearEvidence({marks,dispatch,log,settingsRevision,markKey=null}){
  // Never downgrade a v3 receipt to the legacy public fingerprint if its
  // HMAC key is lost or damaged: that could report a false successful clear.
  const privateMarks=Array.isArray(marks)&&marks.length>0&&
    marks.every(m=>typeof m==='string'&&/^[a-f0-9]{64}$/.test(m));
  if(privateMarks&&(!Buffer.isBuffer(markKey)||markKey.length!==32))
    return {outcome:'uncertain',reason:'MARK_KEY_UNAVAILABLE',
      evidence:{historyTotal:log.total,confirmedCalls:marks.length,settingsEqual:null}};
  if(!Array.isArray(marks)||!marks.length||!marks.every(m=>
    typeof m==='string'&&
    (privateMarks?/^[a-f0-9]{64}$/:/^[a-f0-9]{16}$/).test(m)))
    return {outcome:'uncertain',reason:'MARKS_UNREADABLE',
      evidence:{historyTotal:log.total,settingsEqual:null}};
  const left=new Map();
  for(const mark of callMarks(log,{key:privateMarks?markKey:null}))
    left.set(mark,(left.get(mark)||0)+1);
  let present=0;
  for(const mark of marks)if(left.get(mark)>0){left.set(mark,left.get(mark)-1);present++;}
  const evidence={dispatch:typeof dispatch==='string'?dispatch:'valid',historyTotal:log.total,
    confirmedCalls:marks.length,confirmedStillListed:present,settingsEqual:null};
  if(present===marks.length)
    return {outcome:dispatch==='absent'?'notSent':'notApplied',evidence};
  if(present>0)return {outcome:'uncertain',reason:'PARTIAL_MATCH',evidence};
  if(dispatch==='absent')return {outcome:'uncertain',reason:'HISTORY_GONE_WITHOUT_DISPATCH',evidence};
  if(dispatch==='invalid')return {outcome:'uncertain',reason:'DISPATCH_UNREADABLE',evidence};
  evidence.settingsEqual=typeof dispatch.settingsRevision==='string'&&dispatch.settingsRevision===settingsRevision;
  if(!evidence.settingsEqual)return {outcome:'uncertain',reason:'SETTINGS_CHANGED',evidence};
  return {outcome:'cleared',evidence};
}

export function summarizeCallHistory(body, capturedAt = new Date().toISOString()) {
  const items = parseCallLogJavascript(body);
  // The CGI is normally oldest-first; date ordering is explicit even if a
  // firmware response arrives out of order. Equal-minute rows retain its latest
  // position first, and duplicate records remain separate records.
  const calls=items.map((call,index)=>({call,index,key:callDateKey(call)}))
    .sort((a,b)=>(a.key<b.key?1:a.key>b.key?-1:0)||b.index-a.index).map(row=>row.call);
  return validateCallHistory({
    capturedAt,total:items.length,calls,truncated:false,
  });
}


/**
 * Captures the FIRST CGI response requested by the router's own phones.htm.
 * The native HTML already loads this script through CGIs=["phones","call_log"].
 * Reading it again is unnecessary and can expose a different snapshot.
 *
 * The capture holds telephone numbers in memory only; it never logs raw bodies.
 * A missing, malformed or non-200 initial response fails closed.
 */
export function createFirstCallLogCapture(routerOrigin) {
  if (typeof routerOrigin !== 'string' || !/^http:\/\/[0-9.]+(?::[0-9]+)?$/.test(routerOrigin))
    bad('CALL_LOG_ORIGIN');
  let seen = false;
  let settle;
  const first = new Promise(resolve => { settle = resolve; });
  return {
    observe(response) {
      let url;
      try { url = new URL(response.url()); } catch { return false; }
      if (url.origin !== routerOrigin || url.pathname !== '/cgi/cgi_call_log.js' ||
          response.request().method() !== 'GET' || seen) return false;
      seen = true;
      void Promise.resolve().then(async () => {
        if (response.status() !== 200) bad('CALL_LOG_HTTP');
        // Reject declared oversize responses before materializing their text in
        // Node. The byte count is checked again after decoding; absent/lying
        // headers never disable the actual UTF-8 budget.
        const length=typeof response.headerValue==='function'
          ? await response.headerValue('content-length')
          : typeof response.headers==='function' ? (await response.headers())['content-length'] : null;
        if(length!==null && length!==undefined && /^\d+$/.test(String(length)) &&
            Number(length)>MAX_JS_BYTES) bad('CALL_LOG_TOO_LARGE','CALL_LOG_TOO_LARGE');
        return summarizeCallHistory(await response.text());
      }).then(
        value => settle({ok:true,value}),
        error => settle({ok:false,code:error?.code==='CALL_LOG_TOO_LARGE'?'CALL_LOG_TOO_LARGE':'CALL_LOG_SCHEMA'}),
      );
      return true;
    },
    async read(timeoutMs = 9500) {
      if (!Number.isInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 30000) bad('CALL_LOG_TIMEOUT');
      let timer;
      try {
        const value = await Promise.race([
          first,
          new Promise(resolve => { timer = setTimeout(() => resolve({ok:false}), timeoutMs); }),
        ]);
        if (!value?.ok) bad('CALL_LOG_FIRST_RESPONSE_UNAVAILABLE',value?.code==='CALL_LOG_TOO_LARGE'?'CALL_LOG_TOO_LARGE':'CALL_LOG_SCHEMA');
        return value.value;
      } finally { if (timer) clearTimeout(timer); }
    },
  };
}

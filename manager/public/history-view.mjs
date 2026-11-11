// Pure view helpers: never contact a router, normalize an identifier or write a rule.
export const CALL_LABELS={IN:'Entrante',OUT:'Saliente',MISS:'Perdida'};
export function counterpart(call) { return call.type==='OUT' ? call.destination : call.source; }

function calendarParts(year,month,day) {
  if(year<1 || year>9999 || month<1 || month>12 || day<1) return null;
  const leap=year%4===0 && (year%100!==0 || year%400===0);
  const days=[31,leap?29:28,31,30,31,30,31,31,30,31,30,31];
  return day<=days[month-1] ? {year,month,day} : null;
}
/** Calendar text stays in the router's local calendar; no timezone conversion. */
export function routerDateTimeParts(value) {
  if(typeof value!=='string') return null;
  const m=/^(\d{2})([./])(\d{2})\2(\d{4}) ([01]\d|2[0-3]):([0-5]\d)$/.exec(value);
  if(!m || !calendarParts(Number(m[4]),Number(m[3]),Number(m[1]))) return null;
  return {day:m[4]+'-'+m[3]+'-'+m[1],time:m[5]+':'+m[6],separator:m[2]};
}
export function validCalendarDay(value) {
  if(typeof value!=='string') return false;
  const m=/^(\d{4})-(\d{2})-(\d{2})$/.exec(value);
  return !!(m && calendarParts(Number(m[1]),Number(m[2]),Number(m[3])));
}
/** Empty endpoints are open bounds; every nonempty endpoint must be real. */
export function validateHistoryRange(from='',to='') {
  if(typeof from!=='string' || typeof to!=='string' ||
      (from && !validCalendarDay(from)) || (to && !validCalendarDay(to)))
    return 'Introduce fechas válidas para el intervalo del historial.';
  return from && to && from>to ? 'La fecha inicial no puede ser posterior a la final.' : '';
}
export function callDay(call) {
  return routerDateTimeParts(call?.dateTime)?.day || '';
}
export function callDateKey(call) {
  const parsed=routerDateTimeParts(call?.dateTime);
  return parsed ? parsed.day+' '+parsed.time : '';
}
export function isBlockable(call) { return /^[0-9]{1,32}$/.test(counterpart(call)||''); }

const numericCollator=new Intl.Collator('en',{numeric:true});
export function compareHistoryNumbers(left,right) {
  const a=String(left),b=String(right);
  // Compare arbitrarily long digit strings without coercing to Number.
  if(/^\d+$/.test(a) && /^\d+$/.test(b)) {
    const x=a.replace(/^0+(?=\d)/,''),y=b.replace(/^0+(?=\d)/,'');
    return x.length-y.length || (x<y?-1:x>y?1:0) || (a<b?-1:a>b?1:0);
  }
  return numericCollator.compare(a,b) || (a<b?-1:a>b?1:0);
}
export function queryHistory(calls,{type='ALL',search='',period='all',from='',to='',sort='date-desc'}={},now=new Date()) {
  const query=String(search).trim().toLowerCase();
  const today=new Intl.DateTimeFormat('en-CA',{timeZone:'Atlantic/Canary',year:'numeric',month:'2-digit',day:'2-digit'}).format(now);
  let start=from,end=to;
  if(period==='today') start=end=today;
  else if(period==='7' || period==='30') {
    const d=new Date(today+'T12:00:00Z');d.setUTCDate(d.getUTCDate()-(Number(period)-1));start=d.toISOString().slice(0,10);end=today;
  } else if(period!=='custom') start=end='';
  if(validateHistoryRange(start,end)) return [];
  const result=calls.map((call,index)=>({call,index,day:callDay(call),date:callDateKey(call)})).filter(({call,day})=>{
    return day && (type==='ALL'||call.type===type) && (!start||day>=start) && (!end||day<=end) &&
      (!query || [call.source,call.destination,call.dateTime,CALL_LABELS[call.type]].join(' ').toLowerCase().includes(query));
  });
  const byDate=(a,b)=>a.date<b.date?-1:a.date>b.date?1:0;
  const byNumber=(a,b)=>compareHistoryNumbers(counterpart(a.call),counterpart(b.call));
  return result.sort((a,b)=>(sort==='date-asc'?byDate(a,b):sort==='number-asc'?byNumber(a,b)||byDate(b,a):sort==='number-desc'?byNumber(b,a)||byDate(b,a):byDate(b,a)) || a.index-b.index).map(row=>row.call);
}
export function groupHistory(calls,group='date',sort='date-desc') {
  if(group==='none') return [{key:'',label:'',calls}];
  const groups=new Map();
  for(const call of calls) {
    const key=group==='number'?counterpart(call):callDay(call);
    if(!groups.has(key)) groups.set(key,{key,label:group==='number'?key: (key?key.slice(8)+'/'+key.slice(5,7)+'/'+key.slice(0,4):'Fecha no disponible'),calls:[]});
    groups.get(key).calls.push(call);
  }
  // Group order is independent of whichever row happened to be encountered first.
  // When sorting by another field, dates default to newest first; numbers to ascending.
  const direction=group==='number' ? (sort==='number-desc'?-1:1) : (sort==='date-asc'?1:-1);
  return [...groups.values()].sort((a,b)=>direction*(group==='number'
    ? compareHistoryNumbers(a.key,b.key) : (a.key<b.key?-1:a.key>b.key?1:0)));
}
// Incoming/down-left and outgoing/up-right: open handset in blue.
// Missed: horizontal handset in red with a reflected arrow above it.
export const CALL_ICONS={
  IN:'<svg viewBox="0 0 32 32" fill="none" aria-hidden="true"><path d="M8 5 12 11 9 14c2 4 5 7 9 9l3-3 6 4c-1 4-4 5-7 4C11 25 6 20 4 12c-1-3 0-6 4-7Z"/><path d="m27 5-9 9m0-7v7h7"/></svg>',
  OUT:'<svg viewBox="0 0 32 32" fill="none" aria-hidden="true"><path d="M8 5 12 11 9 14c2 4 5 7 9 9l3-3 6 4c-1 4-4 5-7 4C11 25 6 20 4 12c-1-3 0-6 4-7Z"/><path d="m18 14 9-9m-7 0h7v7"/></svg>',
  MISS:'<svg viewBox="0 0 32 32" fill="none" aria-hidden="true"><path d="M4 22c6-7 18-7 24 0l-2 5-6-2v-4a15 15 0 0 0-8 0v4l-6 2-2-5Z"/><path d="m7 5 9 9 9-9m-6 0h6v6"/></svg>'
};
export const BLOCK_ICON='<svg viewBox="0 0 24 24" fill="none" aria-hidden="true"><circle cx="12" cy="12" r="8.5"/><path d="m6 6 12 12"/></svg>';

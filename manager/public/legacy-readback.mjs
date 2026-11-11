// Shared evidence contract for the native adapter, local session and UI.
// Authentication is never evidence of a data read. Failed reads retain their
// previous observations, with their original timestamps and an explicit status.
export const LEGACY_SECTIONS=Object.freeze(['phone','history','dns']);
const validTime=value=>typeof value==='string'&&Number.isFinite(Date.parse(value));
export const legacyReadVerified=(report,section)=>
  report?.reads?.[section]?.status==='VERIFIED'&&
  validTime(report.reads[section].capturedAt)&&report[section]!=null;
export function legacyCapturedAt(report){
  const dates=LEGACY_SECTIONS.filter(key=>report?.[key]!=null&&validTime(report?.reads?.[key]?.capturedAt))
    .map(key=>report.reads[key].capturedAt);
  return dates.sort((a,b)=>Date.parse(b)-Date.parse(a))[0]??null;
}
export function legacyReadStatus(report){
  const count=LEGACY_SECTIONS.filter(key=>legacyReadVerified(report,key)).length;
  return count===3?'COMPLETE':count?'PARTIAL':'UNVERIFIED';
}
export function withLegacyHistory(report,history){
  const next={...report,history,reachable:true,refreshError:null,
    reads:{...report.reads,history:{status:'VERIFIED',capturedAt:history.capturedAt}},
    capabilities:{...report.capabilities,callHistory:true}};
  next.capturedAt=legacyCapturedAt(next);next.readStatus=legacyReadStatus(next);
  return next;
}
export function mergeLegacyReadback(previous,current){
  const next={...current,reads:{...current.reads}};
  for(const key of [...LEGACY_SECTIONS,'device']){
    if(!legacyReadVerified(current,key)&&previous?.[key]!=null&&validTime(previous?.reads?.[key]?.capturedAt)){
      next[key]=previous[key];
      next.reads[key]={...current.reads?.[key],status:current.reads?.[key]?.status??'UNAVAILABLE',
        capturedAt:previous.reads[key].capturedAt,retained:true};
    }
  }
  next.capturedAt=legacyCapturedAt(next);
  next.readStatus=legacyReadStatus(next);
  return next;
}
export function legacyRefreshFailed(previous,code){
  const current={...previous,attemptedAt:new Date().toISOString(),
    refreshError:code,reachable:null,loggedOut:null,reads:{},capabilities:{...previous.capabilities,
      autodialRead:false,lineRead:false,callHistory:false,dnsRead:false,
      autodialWrite:false,ringTest:false,clearHistory:false}};
  for(const key of LEGACY_SECTIONS)current.reads[key]={status:'ERROR',code};
  return mergeLegacyReadback(previous,current);
}
export function legacyDnsLabel(report,family){
  const dns=report?.dns?.[family];
  if(!dns||typeof dns.connected!=='boolean')return 'No verificado';
  const label=family==='ipv4'?'IPv4':'IPv6';
  const value=dns.connected===false?'Sin conexión '+label+' activa':
    [dns.primary,dns.secondary].filter(Boolean).join(' / ')||'Sin servidores asignados';
  return legacyReadVerified(report,'dns')?value:'Última lectura: '+value+' · sin verificar ahora';
}
export function legacyReadMessage(report){
  if(report?.refreshError)return 'La actualización ha fallado. Se conservan las lecturas anteriores; el acceso y el cierre de sesión nativa no están verificados ahora.';
  const status=legacyReadStatus(report);
  const result=status==='COMPLETE'?'Telefonía, historial y DNS verificados.':status==='PARTIAL'
    ?'Lectura parcial: hay datos verificados y apartados no disponibles.'
    :'Sesión administrativa autenticada, sin lecturas actuales verificadas.';
  return result+(report?.loggedOut===true?' Sesión nativa cerrada.':
    ' No se ha confirmado el cierre de la sesión nativa.');
}
export function legacyFeatureRows(report){
  return [['Historial de llamadas','callHistory'],['Automarcado','autodialWrite'],
    ['Prueba de timbre','ringTest'],['DNS (solo lectura)','dnsRead'],
    ['Bloqueo de llamadas','blocking'],['Cambiar DNS','dnsWrite'],['Vaciar el historial','clearHistory']]
    .map(([label,key])=>({label,status:report?.capabilities?.[key]===true?'Disponible':'No acreditado',
      severity:report?.capabilities?.[key]===true?'supported':'limited'}));
}
export function legacyLocalRows(report,ip,dateLabel){
  const state=key=>{
    const read=report?.reads?.[key];
    const status=read?.status==='VERIFIED'?'Verificada':read?.status==='ERROR'?'Error de lectura':'No disponible';
    return status+(validTime(read?.capturedAt)?' · '+dateLabel(read.capturedAt,true):'')+
      (read?.retained?' · dato anterior conservado':'');
  };
  const ad=report?.phone?.autodial;
  const lines=report?.phone?.lines;
  const lineText=Array.isArray(lines)?lines.map(line=>'Línea '+line.line+': '+
    (line.registered===true?'registrada':line.registered===false?'no registrada':'registro no verificado')+
    (line.number?' · '+line.number:'')).join(' / '):'No verificado';
  const firmware=report?.device?.firmware;
  return [['Modelo',report?.model],['IP del router',ip],['Firmware',firmware?
    firmware+(report?.reads?.device?.status==='VERIFIED'?'':' · lectura anterior'):'No verificado'],
    ['Acceso al router',report?.reachable===true?'Verificado':'No verificado'],
    ['Sesión administrativa',report?.refreshError?'Última autenticación conservada; no verificada ahora':report?.authentication==='VERIFIED'?'Autenticada':'No verificada'],
    ['Lectura de telefonía',state('phone')],['Líneas telefónicas',lineText],
    ['Automarcado',ad?.enabled===true?'Activado':ad?.enabled===false?'Desactivado':'No verificado'],
    ['Número de automarcado',ad?.number??'No verificado'],['Espera antes de marcar',Number.isInteger(ad?.seconds)?ad.seconds+' s':'No verificado'],
    ['Lectura del historial',state('history')],['Lectura DNS',state('dns')],
    ['DNS IPv4',legacyDnsLabel(report,'ipv4')],['DNS IPv6',legacyDnsLabel(report,'ipv6')],
    ['Cierre de sesión nativa',report?.loggedOut===true?'Verificado':'No verificado']];
}

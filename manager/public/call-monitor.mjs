import {newlyRecordedInbound} from './call-enrichment.mjs';

// Voluntary call-history monitor: the subscription, timers and in-flight
// barriers live in one module. Never extends the administrative session.
export function setupCallMonitor({ui,model,api,setActionButton,text,running,
  dateLabel,renderCallHistory,notice,announce,ApiError}){
  const callMonitor={enabled:false,timer:null,inFlight:false,snapshot:null,
    failures:0,checking:false,note:'',generation:0,pendingBaseline:false,
    lastEvent:null,lastEventAt:null};
  const CALL_MONITOR_PERIOD_MS=120000;
  // Only the user's opt-in boolean is stored, scoped to this browser and router.
  // Never persist calls, telephone numbers, passwords, snapshots or tokens.
  const preferenceKey=()=> 'rearouter_call_alerts_v1:'+String(model.routerIp||'');
  function hasSavedPreference(){
    try{return localStorage.getItem(preferenceKey())==='1';}catch{return false;}
  }
  function savePreference(enabled){
    try{
      if(enabled)localStorage.setItem(preferenceKey(),'1');
      else localStorage.removeItem(preferenceKey());
      return true;
    }catch{return false;}
  }
  // Re-arm only once authenticated and a fresh history baseline is available.
  // No permission prompt, no unsolicited historical notifications and no extra
  // router CGI read on reload; normal polling starts two minutes later.
  function restoreCallNotifications(){
    if(callMonitor.enabled||!model.authenticated||model.validatingSession||
       !model.callHistory||model.pending||running()||model.disconnectFailed||
       (model.sessionDeadline&&Date.now()>=model.sessionDeadline)||
       !hasSavedPreference())return false;
    callMonitor.generation++;
    callMonitor.enabled=true;callMonitor.failures=0;
    callMonitor.snapshot=model.callHistory.calls.slice();
    callMonitor.pendingBaseline=false;
    callMonitor.note='Avisos restaurados desde este navegador. Se comprueba cada 2 minutos mientras la página y la sesión estén activas.';
    renderCallNotifications();
    scheduleCallNotifications();
    return true;
  }

function stopCallNotifications(){
  clearTimeout(callMonitor.timer);
  callMonitor.timer=null;callMonitor.enabled=false;
  // Invalidate any in-flight response. Keep inFlight until it actually
  // settles, preventing overlap on rapid disable/re-enable.
  callMonitor.generation++;
  callMonitor.pendingBaseline=false;
  callMonitor.snapshot=null;callMonitor.checking=false;
  callMonitor.failures=0;callMonitor.note='';
  callMonitor.lastEvent=null;callMonitor.lastEventAt=null;
}
function renderCallNotifications(){
  const state=callMonitor.enabled;
  ui.callAlertToggle.disabled=!model.authenticated||model.validatingSession||
    !model.callHistory||!!model.pending||running()||model.disconnectFailed;
  ui.callAlertToggle.setAttribute('aria-pressed',state?'true':'false');
  setActionButton(ui.callAlertToggle,state?'Desactivar avisos de historial':'Avisarme de llamadas registradas',
    state?'bellOff':'bell');
  ui.callAlertToggle.classList.toggle('is-monitoring',state);
  ui.callAlertTest.hidden=!state;
  ui.callAlertTest.disabled=!state||!model.authenticated||model.validatingSession||
    !!model.pending||running()||model.disconnectFailed;
  const permission='Notification' in window?Notification.permission:'unsupported';
  const systemStatus=permission==='granted'?
    'Notificaciones del sistema permitidas.':
    permission==='denied'?
      'El navegador bloquea las notificaciones del sistema; los avisos se mostrarán dentro de la aplicación.':
      'Notificaciones del sistema sin autorizar; comprueba los permisos del navegador.';
  text(ui.callAlertStatus,state?
    (callMonitor.checking?'Comprobando el historial sin prolongar tu sesión…':
    callMonitor.note||'Avisos activados. Se comprueba el historial cada 2 minutos, después de que se registra una llamada.')+
      ' '+systemStatus:
    'Avisos del historial desactivados. Detecta llamadas registradas, no el timbrado en tiempo real.');
  ui.callAlertLatest.hidden=!state||!callMonitor.lastEvent;
  text(ui.callAlertLatest,state&&callMonitor.lastEvent?
    callMonitor.lastEvent+' · Detectada a las '+callMonitor.lastEventAt+'.':'');
}
function scheduleCallNotifications(){
  clearTimeout(callMonitor.timer);callMonitor.timer=null;
  if(!callMonitor.enabled||!model.authenticated)return;
  callMonitor.timer=setTimeout(()=>void checkNewCallNotifications(),CALL_MONITOR_PERIOD_MS);
}
function notifyRecordedInbound(calls){
  const missed=calls.filter(c=>c.type==='MISS').length;
  const number=calls.length;
  const message=number===1?
    (missed?'Nueva llamada perdida registrada.':'Nueva llamada entrante registrada.'):
    number+' nuevas llamadas recibidas en el historial'+(missed?' ('+missed+' perdidas)':'')+'.';
  // A system notification never includes telephone numbers, session tokens or
  // browsing history, which may be visible on the lock screen.
  callMonitor.lastEvent=message;
  callMonitor.lastEventAt=new Date().toLocaleTimeString('es-ES',{hour:'2-digit',minute:'2-digit'});
  callMonitor.note='Último aviso de llamada: '+callMonitor.lastEventAt+
    '. El historial se seguirá comprobando aproximadamente cada 2 minutos.';
  // A system notification must not depend on page visibility; otherwise
  // foreground browsers do not receive one. Keep a visible, persistent fallback.
  if('Notification' in window && Notification.permission==='granted'){
    try {
      const note=new Notification('RuxBox+',{body:message,tag:'rearouter-new-records'});
      note.onclick=()=>{window.focus();note.close();};
    }catch{}
  }
  if(!document.hidden)notice(message,'success');
  renderCallNotifications();
  announce(message);
}
// Shared by the periodic monitor and the manual 'Actualizar llamadas' read.
// Never silently advance the baseline: that would erase a newly recorded call
// if the user refreshes history before the next scheduled monitor poll.
function acceptCallMonitorHistory(history){
  if(!callMonitor.enabled||!history||!Array.isArray(history.calls))return 0;
  const previous=callMonitor.snapshot;
  callMonitor.snapshot=history.calls.slice();
  if(previous===null)return 0; // Initial activation/reconnection baseline.
  const fresh=newlyRecordedInbound(previous,history.calls);
  if(!fresh.length)return 0;
  model.callHistory=history;
  model.historyError='';model.historyAttempted=true;
  renderCallHistory();
  notifyRecordedInbound(fresh);
  return fresh.length;
}
async function checkNewCallNotifications({initial=false}={}){
  if(!callMonitor.enabled||!model.authenticated)return;
  if(callMonitor.inFlight){
    if(initial){
      callMonitor.pendingBaseline=true;
      callMonitor.note='Esperando a que termine la consulta anterior…';
      renderCallNotifications();
    }
    return;
  }
  if(model.pending||running()||model.validatingSession||model.disconnectFailed){
    scheduleCallNotifications();return;
  }
  if(model.sessionDeadline && Date.now()>=model.sessionDeadline){
    stopCallNotifications();renderCallNotifications();return;
  }
  const epoch=model.epoch,generation=callMonitor.generation;
  callMonitor.inFlight=true;callMonitor.checking=true;
  if(initial)callMonitor.pendingBaseline=false;
  renderCallNotifications();
  try{
    const history=await api('/api/calls',{monitor:true});
    if(epoch!==model.epoch||generation!==callMonitor.generation||!callMonitor.enabled)return;
    if(!history||!Array.isArray(history.calls)||!Number.isInteger(history.total)||
      history.total<0||history.calls.length>history.total||
      history.calls.some(c=>!c||!['IN','OUT','MISS'].includes(c.type)||
        typeof c.source!=='string'||typeof c.destination!=='string'||
        typeof c.dateTime!=='string'||typeof c.duration!=='string'))
      throw new ApiError('No se puede validar el historial recibido.','CALL_LOG_SCHEMA');
    acceptCallMonitorHistory(history);
    callMonitor.failures=0;
    callMonitor.note='Avisos activados · última comprobación: '+dateLabel(history.capturedAt)+
      '. Cada 2 minutos; no prolongan tu sesión.';
    // Both periodic and user-triggered reads use the same deduplicating
    // baseline. The initial opt-in never alerts retroactively.
  }catch(error){
    if(epoch!==model.epoch||generation!==callMonitor.generation||!callMonitor.enabled)return;
    if(error?.status===409||error?.code==='BUSY'){
      callMonitor.note='El router estaba ocupado. Se comprobará de nuevo más tarde.';
    }else{
      callMonitor.failures++;
      callMonitor.note='No se ha podido actualizar el aviso automático.';
      if(callMonitor.failures>=3){
        stopCallNotifications();
        savePreference(false); // Do not resurrect a failing monitor after reload.
        notice('Los avisos se han desactivado tras varios errores de lectura.','warning');
      }
    }
  }finally {
    callMonitor.inFlight=false;
    if(epoch===model.epoch&&generation!==callMonitor.generation){
      // A previous subscription never becomes the new subscription's
      // baseline; perform exactly one fresh read after it finishes.
      if(callMonitor.enabled&&callMonitor.pendingBaseline){
        callMonitor.checking=false;
        void checkNewCallNotifications({initial:true});
      }
    }else if(epoch===model.epoch){
      callMonitor.checking=false;
      renderCallNotifications();
      scheduleCallNotifications();
    }
  }
}
// Diagnostic only: no router read, no mutation, never fabricates a call.
async function testCallNotification(){
  if(!callMonitor.enabled||!model.authenticated||model.pending||running())return;
  let permission='Notification' in window?Notification.permission:'unsupported';
  if(permission==='default'){
    try{permission=await Notification.requestPermission();}catch{permission='denied';}
  }
  if(!callMonitor.enabled||!model.authenticated)return;
  if(permission!=='granted'){
    callMonitor.note='El navegador no permite las notificaciones del sistema. Revisa el permiso de este sitio; los avisos dentro de la página siguen disponibles.';
    renderCallNotifications();
    notice('Las notificaciones del navegador no están permitidas para este sitio.','warning');
    return;
  }
  try{
    new Notification('RuxBox+',{body:'Notificación de prueba. No es una llamada real.',tag:'rearouter-test-notification'});
    callMonitor.note='Notificación de prueba solicitada al navegador. Si no aparece, comprueba los permisos del sistema operativo.';
    renderCallNotifications();
    notice('Prueba solicitada al navegador. No se ha consultado el Livebox.','success');
  }catch{
    callMonitor.note='El navegador no pudo mostrar la notificación de prueba.';
    renderCallNotifications();
    notice('No se pudo solicitar la notificación de prueba al navegador.','warning');
  }
}
async function toggleCallNotifications(){
  if(callMonitor.enabled){
    savePreference(false);
    stopCallNotifications();renderCallNotifications();
    notice('Avisos de llamadas desactivados. Se ha desactivado también la preferencia guardada.','success');return;
  }
  if(!model.authenticated||model.pending||running()||!model.callHistory)return;
  callMonitor.generation++;
  const generation=callMonitor.generation;
  callMonitor.enabled=true;callMonitor.snapshot=null;callMonitor.failures=0;
  const preferenceSaved=savePreference(true); // Only after the user's click.
  callMonitor.pendingBaseline=true;
  callMonitor.note=callMonitor.inFlight?
    'Esperando a que termine la consulta anterior…':
    'Preparando los avisos de llamadas registradas…';
  renderCallNotifications();
  // Request OS permission exclusively from an explicit user click.
  if('Notification' in window && Notification.permission==='default'){
    try{await Notification.requestPermission();}catch{}
  }
  if(!callMonitor.enabled||generation!==callMonitor.generation||!model.authenticated)return;
  if(!callMonitor.inFlight)
    callMonitor.note='Avisos activados en esta sesión. Consultando el punto de partida…';
  await checkNewCallNotifications({initial:true});
  if(callMonitor.enabled&&generation===callMonitor.generation&&!callMonitor.pendingBaseline){
    const system='Notification' in window && Notification.permission==='granted';
    notice(!preferenceSaved?
      'Avisos activados en esta página, pero el navegador impide recordar la preferencia.':
      system?'Avisos activados y preferencia guardada en este navegador.':
        'Avisos guardados. Los avisos del sistema no están autorizados; solo se avisará dentro de la página.',
      preferenceSaved?'success':'warning');
  }
}


  return {state:callMonitor,stopCallNotifications,renderCallNotifications,
    toggleCallNotifications,restoreCallNotifications,acceptCallMonitorHistory,testCallNotification};
}

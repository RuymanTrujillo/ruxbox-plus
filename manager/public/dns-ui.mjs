// DNS editor is opt-in and session scoped. Values are never stored in
// localStorage, operation history UI, browser notifications or URL strings.
export function setupDnsUI({ui,model,api,text,notice,render,running,needsReview,refreshLegacy}){
 const state={current:null,mode:null,plan:null,latest:null,review:false,loading:false,
   entered:false,generation:0,committing:false,error:'',
   reconciliation:null,proof:null,inspecting:false,acknowledging:false,
   relay:null,relayLoading:false};
 const ipv4=s=>typeof s==='string'&&/^(?:\d{1,3}\.){3}\d{1,3}$/.test(s)&&
   s.split('.').every(x=>Number(x)<=255&&(x.length===1||x[0]!=='0'))&&
   +s.split('.')[0]!==0&&+s.split('.')[0]<224&&+s.split('.')[0]!==127;
 const pair=()=>({primary:ui.dnsPrimary.value.trim(),secondary:ui.dnsSecondary.value.trim()});
 const inputValid=()=>ipv4(pair().primary)&&ipv4(pair().secondary)&&
    pair().primary!==pair().secondary;
 const available=()=>!model.legacy&&model.authenticated&&!model.validatingSession&&
    !!model.csrf&&!model.pending&&!running()&&!needsReview()&&!state.review&&!state.loading;
 const summary=op=>op?.kind==='mode'?
   op.status==='succeeded'?(op.target?.automatic?
     'Modo DNS automático releído en el Livebox; no se acredita el DNS WAN efectivo ni la persistencia.':
     'Valores DNS estáticos releídos en el mismo perfil; no se acredita el DNS WAN efectivo ni la persistencia.'):
   op.status==='failed'?'No se ha enviado ningún cambio DNS.':
   'El cambio necesita revisión. No vuelvas a guardarlo hasta comprobarlo.':
   op?.status==='succeeded'?
   'Valores DNS releídos tras el envío; no se acredita su uso por el proxy ni su persistencia después de reiniciar.':
   op?.status==='failed'?'No se ha enviado ninguna modificación DNS.':
   op?.status==='reviewRequired'?'Resultado incierto: no repitas el cambio. Consulta primero las DNS del router.':
   op?.status==='resolvedNoPersistentEffect'?'Revisión archivada: se ha observado de nuevo el estado DNS original. No se demuestra ausencia de efectos transitorios.':
   'Estado de operación no disponible.';
 function paint(){
   ui.dnsRefresh.disabled=!model.authenticated||model.validatingSession||!!model.pending||running()||state.loading;
   const mode=state.mode;
   ui.dnsPrimary.disabled=ui.dnsSecondary.disabled=!available()||!mode;
   // DNS_CONF is legacy; the sole visible save action always uses DNS mode.
   ui.dnsPrepare.disabled=true;
   ui.dnsModeStatic.disabled=!available()||!mode||!inputValid()||
     (!mode.automatic&&pair().primary===mode.primary&&pair().secondary===mode.secondary);
   ui.dnsModeAuto.disabled=!available()||!mode||mode.automatic;
   text(ui.dnsModeCurrent,!mode?(state.loading?'Consultando DNS…':'Sin consultar'):
     mode.automatic?'DNS automáticas (operador)':
       'DNS personalizadas: '+mode.primary+' / '+mode.secondary);
   ui.dnsCancel.disabled=state.committing;
   ui.dnsCommit.disabled=state.committing||!state.plan||!model.authenticated;
   ui.dnsRelayCheck.disabled=!!model.legacy||!model.authenticated||model.validatingSession||
     !!model.pending||running()||state.loading||state.relayLoading||
     state.committing||state.inspecting||state.acknowledging;
   const relay=state.relay;
   const observedWan=relay?.wan && typeof relay.wan.primary==='string' &&
     typeof relay.wan.secondary==='string'?
       (relay.wan.primary==='0.0.0.0' && relay.wan.secondary==='0.0.0.0'?
         'DNS WAN sin asignación operativa (0.0.0.0 / 0.0.0.0). ':
         'DNS WAN reportadas por el router: '+relay.wan.primary+' / '+relay.wan.secondary+
           ' (uso por el proxy no acreditado). '):
       'DNS WAN no acreditadas. ';
   const relayMessage=state.relayLoading?
     'Leyendo las DNS WAN y consultando el DNS del Livebox, sin modificar la configuración…':
     relay?.status==='RECURSIVE_EGRESS_OBSERVED'?
       observedWan+'Dos consultas públicas han mostrado IP de salida recursivas para el proxy local. No se puede identificar el proveedor ni la configuración DNS efectiva solo con esta prueba.':
     relay?
       observedWan+'No se ha podido determinar con certeza el servidor DNS usado por el proxy del router.':
       'La configuración WAN no certifica el DNS que utilizan las consultas al Livebox.';
   text(ui.dnsRelayResult,relayMessage);
   const detail=relay?.proxy;
   const relayIp=detail?.relay?.akamai?.ip;
   const secondIp=detail?.relay?.google?.ip;
   const inventory=relay?.dnsInventory;
   const captured=inventory?.capturedFields??0;
   const matched=inventory?.matchingFields;
   // The A record of whoami.akamai.net may be a synthetic captive DNS answer.
   // Neither a returned IP nor a single DNS success proves upstream recursion.
   const verified=relay?.status==='RECURSIVE_EGRESS_OBSERVED';
   const akamaiAnswer=relayIp?(verified?relayIp:'respuesta no acreditada: '+relayIp):'sin respuesta';
   const googleAnswer=secondIp?(verified?secondIp:'respuesta no acreditada: '+secondIp):'sin respuesta';
   const safeDetails=relay?
     'Diagnóstico Akamai: '+akamaiAnswer+
     ' · Diagnóstico Google: '+googleAnswer+
     ' · Campos DNS identificados: '+captured+
     (matched!==null&&matched!==undefined?' de '+matched:'')+
     ' · Captura '+(inventory?.complete?'completa':'incompleta o no acreditada')+
     ' · 0 escrituras de configuración.':'';
   text(ui.dnsRelayDetails,safeDetails);
   ui.dnsRelayDetails.hidden=!relay;
   const labels={
     WAN_IPV4:'DNS WAN IPv4 (no demuestra uso por el proxy)',
     RELAY_CANDIDATES:'Candidatos relacionados con proxy/reenvío (función no demostrada)',
     WAN_IPV6:'DNS WAN IPv6',
     DSL_PROFILES:'Perfiles DSL (no equivalen a la interfaz GPON)',
     LOCAL_HOST_RECORDS:'Registros de nombres y direcciones locales',
     OTHER_DNS:'Otros campos relacionados con DNS'
   };
   const groups=Array.isArray(inventory?.groups)?inventory.groups:[];
   const lines=groups.map(group=>
     (labels[group.category]||'Otros')+' — '+group.count+
     '\n'+(Array.isArray(group.names)&&group.names.length?
       group.names.join(', '):'Ningún identificador en este grupo'));
   const observations=Array.isArray(inventory?.observedValues)?
     inventory.observedValues:[];
   const wanProfiles=observations.filter(x=>/^wan_dns[0-3]$/.test(x.name));
   const dslValues=observations.filter(x=>/^dslx_dns/.test(x.name));
   lines.push('Valores WAN estrictamente validados (NO identifican qué perfil utiliza el proxy):');
   lines.push(wanProfiles.length?wanProfiles.map(x=>x.kind==='ipv4_pair'?
     x.name+' = '+x.primary+' / '+x.secondary:
     x.name+' = formato no validado (valor oculto)').join(', '):
     'No se han acreditado valores WAN adicionales.');
   lines.push('Valores DSL validados (NO confirman la configuración GPON):');
   lines.push(dslValues.length?dslValues.map(x=>
     x.name+' = '+(x.kind==='flag'?(x.value?'1':'0'):x.value)).join(', '):
     'Sin direcciones IPv4 ni indicadores booleanos válidos para mostrar');
   text(ui.dnsRelayInventoryList,inventory?lines.join('\n\n'):'');
   text(ui.dnsRelayInventoryMeta,inventory?
     'Campos totales de firmware: '+(inventory.totalConfigFields??'desconocidos')+
     ' · Coincidencias DNS: '+(matched??'no acreditadas')+
     ' · Nombres mostrados: '+captured+
     ' · Faltantes: '+(inventory.missingFields??'no determinado')+
     ' · Inventario '+(inventory.complete?'completo':'incompleto')+'.':
     'Sin inventario autenticado disponible.');
   ui.dnsRelayInventory.hidden=!relay||!inventory;
   const closed=state.latest?.status==='resolvedNoPersistentEffect';
   ui.dnsReconcilePanel.hidden=!model.authenticated||!(state.review||closed);
   ui.dnsReconcileInspect.disabled=!model.authenticated||!state.review||
     !!model.pending||running()||state.inspecting||state.acknowledging;
   const eligible=state.review&&state.proof?.canAcknowledge===true&&
     state.proof?.classification==='ORIGINAL_STATE_OBSERVED_TWICE'&&
     state.proof?.operationId===state.reconciliation?.operationId;
   ui.dnsReconcileClose.hidden=!eligible;
   ui.dnsReconcileClose.disabled=!eligible||!!model.pending||running()||
     state.inspecting||state.acknowledging;
   ui.dnsReconcileCancel.disabled=state.acknowledging;
   ui.dnsReconcileConfirm.disabled=state.acknowledging||!eligible;
   const reconcileMessage=closed?
     'Conciliación cerrada con comprobación del estado original. No se han reenviado DNS; cualquier nuevo cambio necesita una confirmación distinta.':
     state.inspecting?'Verificando dos lecturas independientes del Livebox, sin modificarlo…':
     state.acknowledging?'Comprobando nuevamente el estado original y archivando la revisión…':
     state.proof?.classification==='ORIGINAL_STATE_OBSERVED_TWICE'?
       'Dos lecturas independientes coinciden con la revisión original. Puedes cerrar la revisión mediante una tercera comprobación explícita.':
     state.proof?.classification==='TARGET_STATE_OBSERVED_TWICE'?
       'Las DNS solicitadas aparecen en dos lecturas. La revisión continúa bloqueada para evitar duplicados.':
     state.proof?'No se ha podido acreditar el estado original. La revisión continúa bloqueada.':
       'Un envío anterior tiene resultado incierto. Solo se permiten lecturas hasta conciliarlo.';
   text(ui.dnsReconcileStatus,reconcileMessage);
   text(ui.dnsCurrentPrimary,state.current?.primary||'—');
   text(ui.dnsCurrentSecondary,state.current?.secondary||'—');
   text(ui.dnsLastRead,state.current?.readAt?
     new Date(state.current.readAt).toLocaleTimeString('es-ES',{hour:'2-digit',minute:'2-digit'}):
     'Sin consultar');
   text(ui.dnsCapability,state.review?'Revisión requerida':
     state.loading?'Consultando':
       state.current?(state.current.automatic?'Automáticas (0.0.0.0)':'Disponible para revisar cambios'):
       'Pendiente de lectura');
   const blocker=state.review||needsReview()?
     'Hay una operación pendiente de revisión. Comprueba su resultado antes de cambiar DNS.':'';
   text(ui.dnsError,state.error||blocker);
   ui.dnsError.hidden=!(state.error||blocker);
   if(state.latest){
     ui.dnsLastOperation.hidden=false;
     text(ui.dnsLastOperation,summary(state.latest));
   }else{ui.dnsLastOperation.hidden=true;text(ui.dnsLastOperation,'');}
 }
 function reset(){
   state.generation++;state.current=null;state.mode=null;state.plan=null;state.latest=null;
   state.review=false;state.loading=false;state.entered=false;
   state.committing=false;state.error='';
   state.proof=null;state.reconciliation=null;
   state.inspecting=false;state.acknowledging=false;
   state.relay=null;state.relayLoading=false;
   ui.dnsPrimary.value=ui.dnsSecondary.value='';
   if(ui.dnsConfirmDialog.open)ui.dnsConfirmDialog.close();
   if(ui.dnsReconcileDialog.open)ui.dnsReconcileDialog.close();
   text(ui.dnsStatus,'Conecta con el router para consultar sus DNS.');
   paint();
 }
 async function readStatus(generation=state.generation){
   try{
     const value=await api('/api/dns/status');
     if(generation!==state.generation||!model.authenticated)return;
     // Show only mode changes in this editor; legacy DNS_CONF history is not the active configuration.
     if(value.modeLatest)state.latest=value.modeLatest;
     else if(state.latest?.kind!=='mode')state.latest=null;
     state.review=value.reviewRequired===true;
     state.reconciliation=value.reconciliation||null;
     state.proof=state.reconciliation?.latest||null;
   }catch(error){
     if(generation===state.generation){
       state.review=true;
       state.error='No se pudo comprobar si hay un cambio DNS pendiente. '+error.message;
     }
   }finally{if(generation===state.generation)paint();}
 }
 async function refresh(){
   if(!model.authenticated||state.loading||model.pending||running())return;
   const generation=state.generation,epoch=model.epoch;
   state.loading=true;state.current=null;state.mode=null;state.plan=null;state.error='';
   state.relay=null;
   ui.dnsPrimary.value=ui.dnsSecondary.value='';
   model.pending='dns-read';
   text(ui.dnsStatus,'Consultando los DNS del Livebox…');
   render();
   try{
     // Read the actual static/automatic mode. wan_dns0 is NOT the saved static pair.
     const mode=await api('/api/dns/mode');
     if(generation!==state.generation||epoch!==model.epoch)return;
     if(typeof mode?.automatic!=='boolean'||typeof mode.primary!=='string'||
       typeof mode.secondary!=='string'||!/^[a-f0-9]{64}$/.test(mode.revision))
       throw Error('El router devolvió una respuesta DNS incompatible.');
     state.mode=mode;state.current=mode;
     ui.dnsPrimary.value=mode.automatic?'':mode.primary;
     ui.dnsSecondary.value=mode.automatic?'':mode.secondary;
     text(ui.dnsStatus,mode.automatic?
       'Escribe las dos DNS que prefieres y pulsa Guardar DNS.':
       'Estos DNS están guardados en el router. Puedes editarlos y guardar los cambios.');
     await readStatus(generation);
   }catch(error){
     if(generation!==state.generation||epoch!==model.epoch)return;
     state.mode=null;state.current=null;state.error=error.message;
     text(ui.dnsStatus,'No se han podido consultar los DNS. Pulsa Actualizar para reintentar; no se ha cambiado el router.');
   }finally{
     if(generation===state.generation&&epoch===model.epoch){
       state.loading=false;model.pending='';render();
     }
   }
 }
 async function prepareMode(target){
   if(!available()||!state.mode)return;
   const epoch=model.epoch,generation=state.generation;
   model.pending='dns-prepare';state.error='';render();
   try{
     const response=await api('/api/dns/mode/prepare',{method:'POST',body:target});
     if(epoch!==model.epoch||generation!==state.generation)return;
     if(!response||response.kind!=='mode'||typeof response.planId!=='string'||!response.previous)
       throw Error('No se pudo validar el plan de modo DNS.');
     state.plan=response;
     const label=m=>m.automatic?'DNS automáticas':m.primary+' / '+m.secondary;
     text(ui.dnsConfirmSummary,
       'Actual: '+label(response.previous)+
       '\nNuevo: '+label(response.proposed)+
       '\n'+(target.automatic?
         'Al volver a automático, el operador podría tardar en renovar sus DNS.':
         'Las nuevas DNS se guardarán en el Livebox. La conexión puede interrumpirse brevemente.'));
     text(ui.dnsConfirmTitle,target.automatic?'¿Usar DNS automáticas?':'¿Guardar estas DNS?');
     text(ui.dnsCommit,target.automatic?'Confirmar DNS automáticas':'Guardar DNS');
     text(ui.dnsConfirmError,'');ui.dnsConfirmError.hidden=true;
     ui.dnsConfirmDialog.showModal();ui.dnsCancel.focus();
   }catch(error){
     if(epoch!==model.epoch||generation!==state.generation)return;
     state.error=error.message;notice(error.message,'error');
   }finally{if(epoch===model.epoch&&generation===state.generation){model.pending='';render();}}
 }
 async function commit(){
   if(!state.plan||state.committing||!available())return;
   const plan=state.plan,epoch=model.epoch,generation=state.generation;
   state.committing=true;model.pending='dns-commit';state.error='';
   render();
   try{
     const response=await api(plan.kind==='mode'?'/api/dns/mode/commit':'/api/dns/commit',{
       method:'POST',body:{planId:plan.planId,confirm:true}
     });
     if(epoch!==model.epoch||generation!==state.generation)return;
     state.plan=null;state.relay=null;
     state.latest=response.operation||null;
     state.review=response.reviewRequired===true||
       state.latest?.status==='reviewRequired';
     ui.dnsConfirmDialog.close();
     notice(summary(state.latest),state.review?'warning':
       state.latest?.status==='succeeded'?'success':'error');
     if(!state.review&&state.latest?.status==='succeeded'){
       state.current=null;
       ui.dnsPrimary.value=ui.dnsSecondary.value='';
     }
     text(ui.dnsStatus,summary(state.latest));
   }catch(error){
     if(epoch!==model.epoch||generation!==state.generation)return;
     state.plan=null;
     state.review=true;
     ui.dnsConfirmDialog.close();
     state.error='No se puede certificar si el Livebox aceptó el envío. No lo repitas. '+error.message;
     notice('Resultado DNS pendiente de revisión. No se enviará de nuevo.','warning');
   }finally{
     if(epoch===model.epoch&&generation===state.generation){
       state.committing=false;model.pending='';render();
       // A status read may recover a durable receipt; it cannot submit.
       await readStatus(generation);
       if(state.latest?.status==='succeeded'&&!state.review&&model.authenticated)
         await refresh();
     }
   }
 }
 async function inspectRelay(){
   if(!model.authenticated||model.validatingSession||model.pending||running()||
     state.loading||state.relayLoading||state.committing||state.inspecting||
     state.acknowledging)return;
   const epoch=model.epoch,generation=state.generation;
   state.relayLoading=true;state.relay=null;
   model.pending='dns-relay-read';render();
   try{
     const result=await api('/api/dns/relay-diagnostics');
     if(epoch!==model.epoch||generation!==state.generation)return;
     if(result?.schema!==1||result?.configurationPosts!==0||
       !['RECURSIVE_EGRESS_OBSERVED','RELAY_INDETERMINATE'].includes(result.status))
       throw Error('Respuesta DNS relay incompatible.');
     state.relay=result;
     notice(result.status==='RECURSIVE_EGRESS_OBSERVED'?
       'Se han observado IP recursivas del proxy; no se acredita su proveedor ni qué configuración WAN utiliza.':
       'No se pudo acreditar el resolvedor DNS del Livebox.',
       'warning');
   }catch(error){
     if(epoch!==model.epoch||generation!==state.generation)return;
     state.error=error.message;
     notice('No se ha cambiado la configuración DNS. '+error.message,'error');
   }finally{
     if(epoch===model.epoch&&generation===state.generation){
       state.relayLoading=false;model.pending='';render();
     }
   }
 }
 async function inspectReview(){
   if(!model.authenticated||!state.review||!!model.pending||running()||
      state.inspecting||state.acknowledging)return;
   // DNS mode and legacy DNS_CONF have distinct receipt/reconciliation contracts.
   // A mode uncertainty is resolved only by observing the proposed mode in a
   // fresh authenticated GET. Never call the DNS_CONF closure for a mode receipt.
   if(state.latest?.kind==='mode'){
     await refresh();
     if(model.authenticated)notice(state.review?
       'El modo DNS todavía no coincide con el solicitado. Se mantiene bloqueado cualquier reenvío.':
       'Modo DNS verificado mediante una nueva lectura. No se ha reenviado ningún cambio.',
       state.review?'warning':'success');
     return;
   }
   const generation=state.generation,epoch=model.epoch;
   state.inspecting=true;state.error='';state.proof=null;
   model.pending='dns-reconcile-read';render();
   try{
     const answer=await api('/api/dns/reconcile/inspect',{method:'POST',body:{}});
     if(generation!==state.generation||epoch!==model.epoch)return;
     if(answer?.status!=='INSPECTED_READ_ONLY'||!answer.evidence)
       throw Error('No se han podido validar ambas lecturas independientes.');
     await readStatus(generation);
     notice('Comprobación de solo lectura finalizada. No se ha reenviado ninguna configuración.',
       answer.evidence.classification==='ORIGINAL_STATE_OBSERVED_TWICE'?'success':'warning');
   }catch(error){
     if(generation!==state.generation||epoch!==model.epoch)return;
     state.error=error.message;notice(error.message,'error');
   }finally{
     if(generation===state.generation&&epoch===model.epoch){
       state.inspecting=false;model.pending='';render();
     }
   }
 }
 function openReconcileDialog(){
   if(!model.authenticated||!state.review||!state.proof?.canAcknowledge||
      !state.reconciliation||state.inspecting||state.acknowledging||
      model.pending||running())return;
   const evidence=state.proof;
   if(evidence.classification!=='ORIGINAL_STATE_OBSERVED_TWICE'||
      evidence.operationId!==state.reconciliation.operationId)return;
   text(ui.dnsReconcileSummary,
     'Dos lecturas independientes han encontrado la revisión DNS anterior al intento. '+
     'Para cerrar se exigirá una tercera lectura coincidente. '+
     'No se enviará ninguna orden DNS_CONF. El recibo original seguirá intacto.');
   ui.dnsReconcileDialog.showModal();
   ui.dnsReconcileCancel.focus();
 }
 async function acknowledgeReview(){
   if(!ui.dnsReconcileDialog.open||!state.review||!state.proof?.canAcknowledge||
      state.acknowledging||!model.authenticated||!!model.pending||running())return;
   const evidence=state.proof,epoch=model.epoch,generation=state.generation;
   if(evidence.classification!=='ORIGINAL_STATE_OBSERVED_TWICE'||
      evidence.operationId!==state.reconciliation?.operationId)return;
   state.acknowledging=true;model.pending='dns-reconcile-close';render();
   try{
     const result=await api('/api/dns/reconcile/acknowledge',{
       method:'POST',body:{operationId:evidence.operationId,evidenceId:evidence.evidenceId,
         confirm:'CONFIRMAR_SIN_EFECTO_PERSISTENTE'}});
     if(generation!==state.generation||epoch!==model.epoch)return;
     if(result?.status!=='RESOLVED_NO_PERSISTENT_EFFECT'||result.configurationPosts!==0)
       throw Error('No consta una conciliación terminada y acreditada.');
     ui.dnsReconcileDialog.close();
     await readStatus(generation);
     notice('Revisión archivada. No se ha enviado DNS_CONF.','success');
   }catch(error){
     if(generation!==state.generation||epoch!==model.epoch)return;
     state.error=error.message;notice('La revisión sigue bloqueada: '+error.message,'error');
   }finally{
     if(generation===state.generation&&epoch===model.epoch){
       state.acknowledging=false;model.pending='';render();
     }
   }
 }
 function enter(){
   if(model.legacy||state.entered||state.loading||!model.authenticated||model.validatingSession||
      !!model.pending||running())return;
   // Mark entered ONLY when a read can start. A busy initial click must not
   // consume the one-shot auto-load or leave a read-only/empty DNS editor.
   state.entered=true;
   void refresh();
 }
 for(const input of [ui.dnsPrimary,ui.dnsSecondary]){
   input.addEventListener('input',()=>{
     state.plan=null;state.error='';paint();
   });
 }
 ui.dnsRefresh.addEventListener('click',()=>void (model.legacy?refreshLegacy():refresh()));
 ui.dnsRelayCheck.addEventListener('click',()=>void inspectRelay());
 ui.dnsModeAuto.addEventListener('click',()=>void prepareMode({automatic:true}));
 // Enter and the visible save button have the same path; never call DNS_CONF.
 ui.dnsForm.addEventListener('submit',event=>{
   event.preventDefault();
   if(!available()||!state.mode)return;
   if(!inputValid()){
     state.error='Introduce dos direcciones IPv4 válidas y diferentes.';paint();return;
   }
   const target={automatic:false,...pair()};
   if(!state.mode.automatic&&target.primary===state.mode.primary&&
      target.secondary===state.mode.secondary)return;
   void prepareMode(target);
 });
 ui.dnsCommit.addEventListener('click',()=>void commit());
 ui.dnsCancel.addEventListener('click',()=>{
   if(!state.committing){state.plan=null;ui.dnsConfirmDialog.close();paint();}
 });
 ui.dnsReconcileInspect.addEventListener('click',()=>void inspectReview());
 ui.dnsReconcileClose.addEventListener('click',()=>openReconcileDialog());
 ui.dnsReconcileConfirm.addEventListener('click',()=>void acknowledgeReview());
 ui.dnsReconcileCancel.addEventListener('click',()=>{
   if(!state.acknowledging){ui.dnsReconcileDialog.close();paint();}
 });
 ui.dnsReconcileDialog.addEventListener('cancel',event=>{
   if(state.acknowledging)event.preventDefault();
 });
 ui.dnsConfirmDialog.addEventListener('cancel',event=>{
   if(state.committing)event.preventDefault();
   else state.plan=null;
 });
 function renderDns(){
   paint();
   // Retry the first automatic read once an unrelated manager task finishes.
   if(model.activeView==='dns'&&!state.entered)enter();
 }
 paint();
 return {enter,render:renderDns,reset};
}

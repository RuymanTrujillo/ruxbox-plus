import {routerLocalRows,routerNetworkRows,routerFeatureRows} from './router-info-model.mjs';
import {legacyLocalRows,legacyFeatureRows,legacyReadMessage} from './legacy-readback.mjs';

// Cached per authenticated UI epoch + router IP. No credentials or CGI payloads
// are persisted; only projected, bounded result objects stay in memory.
// Requests are coalesced while a modal is closed/reopened.
export function setupRouterInfoDialog({ui,model,api,make,text,dateLabel,refreshLegacy}){
 let deviceInfo=null,publicInfo=null,cacheKey=null;
 let nativeRequest=null,publicRequest=null,dialogGeneration=0;

 function sessionKey(){return String(model.epoch)+'|'+String(model.routerIp||'');}
 function ensureScope(){
   const next=sessionKey();
   if(cacheKey!==next){
     cacheKey=next;deviceInfo=null;publicInfo=null;
     nativeRequest=null;publicRequest=null;
   }
 }
 function canShow(generation,key){
   return ui.routerInfoDialog.open&&generation===dialogGeneration&&
     model.authenticated&&cacheKey===key&&sessionKey()===key;
 }
 function updateRefreshButton(){
   const loading=!!nativeRequest||!!publicRequest||!!model.pending||model.serverBusy;
   ui.routerInfoReload.disabled=loading||!model.authenticated;
   ui.routerInfoReload.classList.toggle('is-loading',loading);
   const caption=ui.routerInfoReload.querySelector('.button-caption');
   if(caption)text(caption,loading?'Actualizando…':'Actualizar');
 }
 function setRouterInfoList(container,items){
   const fragment=document.createDocumentFragment();
   for(const [label,value] of items){
     const row=make('div','router-info-field');
     row.append(make('dt','router-info-label',label),
       make('dd','router-info-value',value == null || value === '' ? 'No disponible' : String(value)));
     fragment.append(row);
   }
   container.replaceChildren(fragment);
 }
 function renderRouterInfoFunctions(){
   const items=model.legacy?legacyFeatureRows(model.legacy):routerFeatureRows(model.state?.compatibility?.features);
   ui.routerInfoFunctions.replaceChildren(...items.map(({label,status,severity})=>{
     const row=make('div','router-info-function');
     row.append(make('span','',label),make('strong',
       severity==='supported'?'router-info-ok':'router-info-caution',status));
     return row;
   }));
 }
 function renderNative(info){
   if(model.legacy){
     setRouterInfoList(ui.routerInfoLocal,legacyLocalRows(model.legacy,model.routerIp,dateLabel));
     text(ui.routerInfoLocalStatus,legacyReadMessage(model.legacy));
     ui.routerInfoLocalReload.hidden=true;
     renderRouterInfoFunctions();
     return;
   }
   setRouterInfoList(ui.routerInfoLocal,routerLocalRows(model.state,model.routerIp,dateLabel,info));
   const dns=info?.localNameSource==='local-dns-ptr-forward-confirmed';
   text(ui.routerInfoLocalStatus,'Datos del Livebox obtenidos. '+
     (dns?'Nombre local verificado por DNS.':'Nombre local no verificado por DNS.'));
   ui.routerInfoLocalReload.hidden=true;
   renderCompatibility();
 }
 function renderPublic(info){
   setRouterInfoList(ui.routerInfoNetwork,routerNetworkRows(info,dateLabel));
   text(ui.routerInfoNetworkStatus,'Datos de conexión disponibles.');
 }
 function setBusy(kind,busy){
   const status=kind==='native'?ui.routerInfoLocalStatus:ui.routerInfoNetworkStatus;
   status.classList.toggle('is-loading',busy);
   const section=status.closest('.router-info-section');
   if(section)section.setAttribute('aria-busy',busy?'true':'false');
 }
 async function loadNativeRouterInfo({force=false}={}){
   if(!ui.routerInfoDialog.open||!model.authenticated)return;
   if(model.legacy){
     if(force)await refreshLegacy();
     if(ui.routerInfoDialog.open&&model.legacy)renderNative();
     updateRefreshButton();return;
   }
   ensureScope();
   const generation=dialogGeneration,key=cacheKey;
   if(deviceInfo&&!force&&!nativeRequest){renderNative(deviceInfo);return;}
   ui.routerInfoLocalReload.hidden=true;
   text(ui.routerInfoLocalStatus,'Consultando modelo, firmware y datos del Livebox…');
   setBusy('native',true);
   if(!nativeRequest){
     let task;
     task=api('/api/router/device-info').then(info=>{
       if(!info||info.source!=='livebox-native-system-cgi'||
         typeof info.hardwareModel!=='string'||!info.hardwareModel||
         typeof info.firmwareDisplay!=='string'||!info.firmwareDisplay)
         throw Error('DEVICE_INFO_SCHEMA');
       if(cacheKey===key&&sessionKey()===key&&model.authenticated)deviceInfo=info;
       return info;
     }).finally(()=>{
       if(nativeRequest===task)nativeRequest=null;
       updateRefreshButton();
     });
     nativeRequest=task;
   }
   updateRefreshButton();
   try{
     const info=await nativeRequest;
     if(canShow(generation,key))renderNative(info);
   }catch{
     if(canShow(generation,key)){
       text(ui.routerInfoLocalStatus,deviceInfo?
         'No se pudo actualizar. Se conservan los datos anteriores.':
         'No se pudieron consultar los datos del Livebox.');
       ui.routerInfoLocalReload.hidden=false;
     }
   }finally{
     if(canShow(generation,key))setBusy('native',false);
     updateRefreshButton();
   }
 }
 async function loadPublicRouterInfo({force=false}={}){
   if(!ui.routerInfoDialog.open||!model.authenticated)return;
   if(model.legacy){
     setRouterInfoList(ui.routerInfoNetwork,[['Conexión a Internet','No verificada para este router']]);
     text(ui.routerInfoNetworkStatus,'La conexión de este equipo no acredita la conexión del router seleccionado.');
     return;
   }
   ensureScope();
   const generation=dialogGeneration,key=cacheKey;
   if(publicInfo&&!force&&!publicRequest){renderPublic(publicInfo);return;}
   text(ui.routerInfoNetworkStatus,'Consultando los datos de conexión a Internet…');
   setBusy('public',true);
   if(!publicRequest){
     let task;
     task=api('/api/router/public-network').then(info=>{
       // Projection also verifies that the endpoint returned an expected record.
       routerNetworkRows(info,dateLabel);
       if(cacheKey===key&&sessionKey()===key&&model.authenticated)publicInfo=info;
       return info;
     }).finally(()=>{
       if(publicRequest===task)publicRequest=null;
       updateRefreshButton();
     });
     publicRequest=task;
   }
   updateRefreshButton();
   try{
     const info=await publicRequest;
     if(canShow(generation,key))renderPublic(info);
   }catch{
     if(canShow(generation,key)){
       text(ui.routerInfoNetworkStatus,publicInfo?
         'No se pudo actualizar. Se conservan los datos anteriores.':
         'No se pudieron consultar los datos de conexión.');
     }
   }finally{
     if(canShow(generation,key))setBusy('public',false);
     updateRefreshButton();
   }
 }
 function openRouterInfo(){
   if(!model.authenticated||model.validatingSession||(!model.state&&!model.legacy)||ui.compatBadge.hidden)return;
   ensureScope();
   dialogGeneration++;
   setRouterInfoList(ui.routerInfoLocal,routerLocalRows(model.state,model.routerIp,dateLabel,deviceInfo));
   if(publicInfo)setRouterInfoList(ui.routerInfoNetwork,routerNetworkRows(publicInfo,dateLabel));
   else ui.routerInfoNetwork.replaceChildren();
   renderRouterInfoFunctions();
   ui.routerInfoDialog.showModal();
   ui.routerInfoDialog.scrollTop=0;
   ui.routerInfoTitle.focus({preventScroll:true});
   ui.routerInfoReload.hidden=false;
   if(deviceInfo)renderNative(deviceInfo);
   if(publicInfo)renderPublic(publicInfo);
   updateRefreshButton();
   void loadNativeRouterInfo();
   void loadPublicRouterInfo();
 }
 function refreshBoth(){
   if(!ui.routerInfoDialog.open||!model.authenticated||nativeRequest||publicRequest)return;
   void loadNativeRouterInfo({force:true});
   void loadPublicRouterInfo({force:true});
 }
 ui.compatBadge.addEventListener('click',openRouterInfo);
 ui.routerInfoClose.addEventListener('click',()=>ui.routerInfoDialog.close());
 ui.routerInfoReload.addEventListener('click',refreshBoth);
 ui.routerInfoLocalReload.addEventListener('click',()=>void loadNativeRouterInfo({force:true}));
 ui.routerInfoDialog.addEventListener('close',()=>{
   // A queued close event must not clear a dialog already reopened.
   if(ui.routerInfoDialog.open)return;
   dialogGeneration++;
   ui.routerInfoLocalStatus.classList.remove('is-loading');
   ui.routerInfoNetworkStatus.classList.remove('is-loading');
   for(const section of ui.routerInfoDialog.querySelectorAll('.router-info-section'))
     section.setAttribute('aria-busy','false');
   text(ui.routerInfoLocalStatus,'');
   text(ui.routerInfoNetworkStatus,'');
   ui.routerInfoLocalReload.hidden=true;
   ui.routerInfoLocal.replaceChildren();
   ui.routerInfoNetwork.replaceChildren();
   ui.routerInfoFunctions.replaceChildren();
   // Preserve cached successful reads; reopen restores them without another GET.
   if(model.authenticated&&!ui.compatBadge.hidden)ui.compatBadge.focus();
 });
 function renderCompatibility(){
   if(model.authenticated&&!model.validatingSession&&model.legacy){
     ui.compatBadge.hidden=false;ui.compatibilityHelp.hidden=false;
     ui.compatBadge.classList.add('is-limited');
     text(ui.compatBadge,'Compatibilidad limitada');
     text(ui.compatibilityDescription,model.legacy.model+'. '+legacyReadMessage(model.legacy));
     ui.compatibilityFeatures.replaceChildren(...legacyFeatureRows(model.legacy).map(({label,status,severity})=>{
       const el=make('li');el.append(make('span','',label),make('strong',severity==='supported'?'is-supported':'is-limited',status));return el;
     }));
     if(ui.routerInfoDialog.open)renderNative();
     updateRefreshButton();return;
   }
   const data=model.authenticated&&!model.validatingSession?model.state?.compatibility:null;
   const ready=data&&['compatible','limited'].includes(data.status)&&data.features;
   ui.compatBadge.hidden=!ready;
   ui.compatibilityHelp.hidden=!ready;
   if(!ready) {
     text(ui.compatBadge,'');
     text(ui.compatibilityDescription,'');
     ui.compatibilityFeatures.replaceChildren();
     if(!model.authenticated){deviceInfo=null;publicInfo=null;cacheKey=null;}
     return;
   }
   const complete=data.status==='compatible';
   ui.compatBadge.classList.toggle('is-limited',!complete);
   text(ui.compatBadge,complete?'Compatibilidad comprobada':'Compatibilidad limitada');
   text(ui.compatibilityDescription,
     (deviceInfo?.hardwareModel||data.model)+' · Firmware: '+
       (deviceInfo?.firmwareDisplay||data.firmware||'No disponible')+
     '. Perfil: '+data.profile+'. '+(complete?
       'Las estructuras y órdenes conocidas coinciden.':
       'Se han detectado diferencias. Solo se permiten las funciones acreditadas.'));
   const checks=routerFeatureRows(data.features,{forHelp:true});
   ui.compatibilityFeatures.replaceChildren(...checks.map(({label,status,severity})=>{
     const el=make('li');
     el.append(make('span','',label),make('strong',
       severity==='supported'?'is-supported':
       severity==='on-demand'?'is-on-demand':'is-limited',status));
     return el;
   }));
 }
 return {renderCompatibility};
}

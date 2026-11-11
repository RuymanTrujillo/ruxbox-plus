import {validateCallHistory} from './call-history.mjs';
import {withLegacyHistory} from './public/legacy-readback.mjs';

// Read-only HTTP routes; session and mutation state stay with the owner.
export function createReadRoutes({
  json,fault,requireSession,assertCurrentSession,getHealth,
  publicNetworkInfo,routerSettings,localRouterNameLookup,projectRouterDeviceInfo,getAuthorizedSessionId,getActiveWork,
  unresolved,driver,routerWork,clearReview,lastClear,clearPublic,pendingClear,
  recent,publicOperation,snapshotOf,reconcile,stateView,getCached,setCached
}){
  return async function handleReadRoute(req,res,route){
    if(req.method!=='GET')return false;
      if (req.method === 'GET' && route === '/api/health') {
        json(res,200,getHealth());return true;
      }
      if(route==='/api/router/wan-native-inspection'){
        const session=requireSession(req,true,false);
        if(typeof driver.readWanNative!=='function')throw fault('READ_UNAVAILABLE',503);
        let raw;
        try{
          raw=await routerWork('wan-native-readonly',async signal=>
            driver.readWanNative(session.password,{signal}),req);
        }catch(error){
          if(['AUTH_FAILED','AUTH_USER','NOT_AUTHENTICATED','REQUEST_CANCELLED','BUSY'].includes(error?.code))
            throw error;
          // Native failures may include sensitive CGI details. Never reflect
          // exception text, URLs, stack or raw firmware bytes to the caller.
          assertCurrentSession(session,true);
          const code=['READ_UNAVAILABLE','ROUTER_TIMEOUT','DNS_PAGE_UNAVAILABLE','NETWORK_ERROR']
            .includes(error?.code)?error.code:'UNCLASSIFIED';
          json(res,200,{schema:1,status:'NATIVE_DRIVER_NOT_VERIFIED',
            diagnosticCode:code,readOnly:true,configurationPosts:0,pages:[],
            note:'No se pudo obtener una lectura nativa acreditada. Ningún comando WAN ejecutado.'});
          return true;
        }
        assertCurrentSession(session,true);
        const expected=['/advanced_network_configuration.htm','/advanced_network_upnp.htm'];
        const knownCommands=new Set(['WAN_CONN','WAN_DISC','WANETH_CONN','WANETH_DISC',
          'wan_start','wan_stop','subFormWANConn','subFormWANDisc',
          'subFormWANETHConn','subFormWanEthDisc']);
        const safeName=x=>typeof x==='string'&&/^[a-z][a-z0-9_-]{0,55}$/i.test(x)&&
          !/pass|token|cookie|secret|key|auth|csrf|session|serial|ssid|pin|user/i.test(x);
        const count=n=>Number.isSafeInteger(n)&&n>=0&&n<=5000;
        const htmlLength=n=>Number.isSafeInteger(n)&&n>=0&&n<=131072;
        if(raw?.schema!==1||raw.configurationPosts!==0||
          !Array.isArray(raw.pages)||raw.pages.length!==2)
          throw fault('READ_UNAVAILABLE',502);
        const validStatus=/^(HTML_INSPECTED|REDIRECT_OR_LOGIN|UNEXPECTED_CONTENT_TYPE|BODY_TOO_LARGE|EMPTY_RESPONSE|READ_TIMEOUT|READ_UNAVAILABLE|HTTP_[1-5][0-9]{2})$/;
        // The native router can use unexpected form actions, methods, script
        // names or identifiers. An unknown value must be REDACTED, not turned
        // into a 502 that hides otherwise useful read-only observations.
        const pages=raw.pages.map((item,i)=>{
          if(item?.path!==expected[i]||typeof item.status!=='string'||
            !htmlLength(item.htmlBytes)||
            !Array.isArray(item.forms)||!Array.isArray(item.controls)||
            !Array.isArray(item.commands)||!Array.isArray(item.functions)||
            !Array.isArray(item.linkedScripts))
            throw fault('READ_UNAVAILABLE',502);
          const forms=item.forms.slice(0,25).map(form=>({
            method:['GET','POST'].includes(form?.method)?form.method:'OTHER',
            actionPath:['','/apply_abstract.cgi','/login.cgi'].includes(form?.actionPath)?
              form.actionPath:'REDACTED',
            fieldCount:count(form?.fieldCount)?form.fieldCount:null,
            hasHiddenFields:form?.hasHiddenFields===true
          }));
          const controls=item.controls.slice(0,70).filter(el=>
            ['a','button','input'].includes(el?.tag)).map(el=>({
            tag:el.tag,
            id:safeName(el?.id)?el.id:null,
            hasClickHandler:el?.hasClickHandler===true,
            relatedCommands:Array.isArray(el?.relatedCommands)?
              [...new Set(el.relatedCommands.filter(x=>knownCommands.has(x)))].slice(0,10):[]
          }));
          const commands=item.commands.slice(0,20).filter(cmd=>
            knownCommands.has(cmd?.name)).map(cmd=>({
            name:cmd.name,
            scriptReferences:count(cmd?.scriptReferences)?cmd.scriptReferences:null,
            handlerReferences:count(cmd?.handlerReferences)?cmd.handlerReferences:null,
            hasFormDispatchReference:cmd?.hasFormDispatchReference===true
          }));
          const functions=item.functions.filter(safeName).slice(0,24);
          const linkedScripts=item.linkedScripts.filter(x=>typeof x==='string'&&
            /^\/(?:cgi|js)\/[a-z0-9_-]{1,70}\.js$/i.test(x)&&
            !/pass|token|cookie|secret|key|auth|session/i.test(x)).slice(0,30);
          return {path:item.path,status:validStatus.test(item.status)?item.status:'READ_UNAVAILABLE',
            htmlBytes:item.htmlBytes,forms,controls,commands,functions,linkedScripts,
            truncated:{
              forms:item.forms.length>25,controls:item.controls.length>70,
              commands:item.commands.length>20,functions:item.functions.length>24,
              linkedScripts:item.linkedScripts.length>30
            }};
        });
        json(res,200,{schema:1,status:'NATIVE_INSPECTION_COMPLETED',
          readOnly:true,configurationPosts:0,pages,
          note:'Metadatos de HTML autenticado, sin valores, código bruto ni credenciales. Ningún comando WAN ejecutado.'});
        return true;
      }
      if (route === '/api/router/device-info') {
        const session=requireSession(req,true,false);
        if(typeof driver.readDeviceInfo!=='function')throw fault('DEVICE_INFO_UNAVAILABLE',503);
        const ip=routerSettings.get().routerIp;
        // Both operations read-only: two authenticated native CGI GETs and
        // local DNS. They never update the operations journal or renew TTL.
        const lookup=Promise.resolve().then(()=>localRouterNameLookup(ip)).catch(()=>null);
        const raw=await routerWork('device-info',async signal=>
          driver.readDeviceInfo(session.password,{signal}),req);
        let device;
        try{device=projectRouterDeviceInfo(raw);}
        catch{throw fault('DEVICE_INFO_SCHEMA',502);}
        const local=await lookup;
        assertCurrentSession(session,true);
        const hostname=local?.source==='local-dns-ptr-forward-confirmed'&&
          typeof local.hostname==='string'&&/^[a-z0-9][a-z0-9.-]{0,251}[a-z0-9]$/iu.test(local.hostname)?
          local.hostname:null;
        json(res,200,{...device,localHostname:hostname,
          localNameSource:hostname?'local-dns-ptr-forward-confirmed':null});
        return true;
      }
      if (req.method === 'GET' && route === '/api/router/public-network') {
        const session=requireSession(req,true,false);
        // HTTPS third-party request is a deliberate UI action, not a
        // router CGI request; it never renews the admin session.
        let info;
        try{info=await publicNetworkInfo();}
        catch{throw fault('ISP_LOOKUP_UNAVAILABLE',503);}
        assertCurrentSession(session,true);
        json(res,200,info);return true;
      }
      if (req.method === 'GET' && route === '/api/settings') {
        requireSession(req);
        json(res,200,{...routerSettings.get(),canChange:!getAuthorizedSessionId() && !getActiveWork() && !unresolved()}); return true;
      }
      if (req.method === 'GET' && route === '/api/calls') {
        // Same-origin explicit monitor GET reuses the existing read-only driver
        // but cannot renew the 30-minute administrative session. Ordinary
        // user-triggered refresh keeps the previous behavior.
        const monitor = req.headers['x-rearouter-monitor'] === '1';
        const session = requireSession(req, true, !monitor);
        // The old firmware has its own call-log adapter (call_log.xml).
        const source = session.legacy ? driver.legacy : driver;
        if (typeof source?.readCalls !== 'function') throw fault('READ_UNAVAILABLE', 502);
        const log = await routerWork('call-history', async signal =>
          validateCallHistory(await source.readCalls(session.password, {signal})), req);
        assertCurrentSession(session,true);
        if(session.legacy)session.legacy=withLegacyHistory(session.legacy,log);
        json(res, 200, log); return true;
      }
      if (req.method === 'GET' && route === '/api/calls/clear/status') {
        requireSession(req,true);
        json(res,200,{attempt:lastClear()?clearPublic(lastClear()):null,reviewRequired:clearReview(),
          review:pendingClear()?clearPublic(pendingClear()):null});return true;
      }
      if (req.method === 'GET' && route === '/api/operations') {
        requireSession(req, true);
        json(res, 200, {operations: recent().slice(0, 100).map(publicOperation)}); return true;
      }
      if (req.method === 'GET' && route === '/api/state') {
        const session = requireSession(req, true);
        if (!getActiveWork()) {
          const latest = await routerWork('read', async signal => {
            const snapshot = snapshotOf(await driver.read(session.password, {signal}));
            signal.throwIfAborted(); assertCurrentSession(session, true);
            await reconcile(snapshot); return snapshot;
          }, req);
          setCached(latest);
        }
        if (!getCached()) throw fault('BUSY', 409);
        json(res, 200, stateView(getCached())); return true;
      }
    return false;
  };
}

import fs from 'node:fs/promises';
import path from 'node:path';
import {randomUUID,createHash} from 'node:crypto';
import {validateDnsPair,validateDnsModeTarget} from './dns-core.mjs';
import {createDnsReconciliation} from './dns-reconciliation.mjs';
import {probeDnsRelay,describeNativeDnsInventory} from './dns-relay-probe.mjs';

const uuid=/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/u;
const sha=value=>createHash('sha256').update(value).digest('hex');
const iso=()=>new Date().toISOString();
async function writeExclusive(file,obj){
 const handle=await fs.open(file,'wx',0o600);
 try{await handle.writeFile(JSON.stringify(obj,null,2)+'\n','utf8');await handle.sync();}
 finally{await handle.close();}
}
async function replaceAtomic(file,obj){
 const tmp=file+'.'+randomUUID()+'.tmp';
 await writeExclusive(tmp,obj);await fs.rename(tmp,file);
}
export async function createDnsWorkflow({
  dataDir,driver,requireSession,routerWork,assertCurrentSession,json,bodyOf,
  objectBody,fault,unresolved=()=>false,otherReview=()=>false,
  planTtlMs=120000,relayProbe=probeDnsRelay,getRouterIp=()=> '192.168.1.1'
}){
 if(typeof dataDir!=='string'||!dataDir||!driver||
   typeof requireSession!=='function'||typeof routerWork!=='function'||
   typeof assertCurrentSession!=='function'||typeof json!=='function'||
   typeof bodyOf!=='function'||typeof objectBody!=='function'||typeof fault!=='function'||
   typeof relayProbe!=='function'||typeof getRouterIp!=='function')
   throw Error('INVALID_DNS_WORKFLOW');
 const diagnosticFile=path.join(dataDir,'dns-diagnostic.json');
 const acceptedCodes=new Set([
   'OK','DNS_PAGE_UNAVAILABLE','DNS_FUNCTIONS_MISSING','DNS_COMMAND_MISSING',
   'DNS_FIELD_MISSING','DNS_SCHEMA','DNS_UNAVAILABLE','DNS_FORM_MISMATCH',
   'DNS_UNCHANGED','ROUTER_TIMEOUT','ROUTER_UNAVAILABLE','BUSY',
   'REQUEST_CANCELLED','NOT_AUTHENTICATED','DNS_REVIEW_REQUIRED','STALE_PLAN'
 ]);
 let lastDiagnostic=null;
 try{
   const previous=JSON.parse(await fs.readFile(diagnosticFile,'utf8'));
   if(previous?.schema===1&&['read','prepare'].includes(previous.action)&&
      acceptedCodes.has(previous.code)&&!Number.isNaN(Date.parse(previous.at)))
      lastDiagnostic={schema:1,action:previous.action,code:previous.code,at:previous.at};
 }catch{}
 const recordDiagnostic=async(action,code)=>{
   const summary={schema:1,action,
     code:acceptedCodes.has(code)?code:'ROUTER_UNAVAILABLE',at:iso()};
   lastDiagnostic=summary;
   // Metadata only: no DNS addresses, passwords, tokens, session IDs or CGI.
   try{await replaceAtomic(diagnosticFile,summary);}catch{}
 };
 const folder=path.join(dataDir,'dns-operations');
 await fs.mkdir(folder,{recursive:true,mode:0o700});
 const attempts=new Map(),plans=new Map();
 for(const entry of await fs.readdir(folder,{withFileTypes:true})){
  if(!entry.isDirectory())continue;
  // An unknown or partial attempt blocks additional DNS writes, never reads.
  let attempt={id:entry.name,status:'reviewRequired',phase:'uncertain',
    createdAt:iso(),configurationPosts:null,
    message:'Intento DNS anterior incompleto. Consultar antes de repetir cambios.'};
  try{
    if(!uuid.test(entry.name))throw Error('DNS_RECORD_INVALID');
    const reservation=JSON.parse(await fs.readFile(path.join(folder,entry.name,'reservation.json'),'utf8'));
    if(reservation.version!==1||reservation.id!==entry.name||
      !Number.isFinite(Date.parse(reservation.createdAt))||
      !/^[a-f0-9]{64}$/.test(reservation.revision))
      throw Error('DNS_RECORD_INVALID');
    const target=validateDnsPair(reservation.target);
    attempt={...attempt,createdAt:reservation.createdAt,target};
    const result=JSON.parse(await fs.readFile(path.join(folder,entry.name,'result.json'),'utf8'));
    if(result.version!==1||result.id!==entry.name||
      !['succeeded','failed','reviewRequired'].includes(result.status)||
      ![0,1,null].includes(result.configurationPosts)||
      typeof result.message!=='string'||result.message.length>500||
      !Number.isFinite(Date.parse(result.finishedAt)))throw Error('DNS_RECORD_INVALID');
    attempt={...attempt,status:result.status,phase:result.phase||'complete',
      configurationPosts:result.configurationPosts,finishedAt:result.finishedAt,
      message:result.message};
  }catch{}
  attempts.set(entry.name,attempt);
 }
 const latest=()=>[...attempts.values()].sort((a,b)=>b.createdAt.localeCompare(a.createdAt))[0]||null;
 const reconciliation=await createDnsReconciliation({
   dataDir,attempts,driver,routerWork,assertCurrentSession,json,bodyOf,objectBody,fault
 });
 // Static/automatic mode changes (ui_dns over dslx_dns* rows) keep their own
 // receipts. Any incomplete or uncertain one blocks every DNS write.
 const modeFolder=path.join(dataDir,'dns-mode-operations');
 await fs.mkdir(modeFolder,{recursive:true,mode:0o700});
 const modeAttempts=new Map();
 for(const entry of await fs.readdir(modeFolder,{withFileTypes:true})){
  if(!entry.isDirectory())continue;
  let attempt={id:entry.name,kind:'mode',status:'reviewRequired',createdAt:iso(),
    configurationPosts:null,target:null,beforeRevision:null,
    message:'Cambio de modo DNS anterior incompleto. Consulta el modo antes de repetirlo.'};
  try{
    if(!uuid.test(entry.name))throw Error('DNS_RECORD_INVALID');
    const r=JSON.parse(await fs.readFile(path.join(modeFolder,entry.name,'reservation.json'),'utf8'));
    if(r.version!==1||r.id!==entry.name||!/^[a-f0-9]{64}$/.test(r.revision)||
      !Number.isFinite(Date.parse(r.createdAt)))throw Error('DNS_RECORD_INVALID');
    attempt={...attempt,createdAt:r.createdAt,target:validateDnsModeTarget(r.target),beforeRevision:r.revision,
      profileRoute:/^[0-3]$/.test(r.profileRoute)?r.profileRoute:null};
    const result=JSON.parse(await fs.readFile(path.join(modeFolder,entry.name,'result.json'),'utf8'));
    if(result.version!==1||result.id!==entry.name||
      !['succeeded','failed','reviewRequired'].includes(result.status)||
      ![0,1,null].includes(result.configurationPosts)||typeof result.message!=='string'||
      !Number.isFinite(Date.parse(result.finishedAt)))throw Error('DNS_RECORD_INVALID');
    attempt={...attempt,status:result.status,configurationPosts:result.configurationPosts,
      finishedAt:result.finishedAt,message:result.message};
  }catch{}
  modeAttempts.set(entry.name,attempt);
 }
 const modeOpen=()=>[...modeAttempts.values()].some(a=>a.status==='reviewRequired');
 const modeLatest=()=>[...modeAttempts.values()].sort((a,b)=>b.createdAt.localeCompare(a.createdAt))[0]||null;
 const publicMode=a=>a?{id:a.id,kind:'mode',status:a.status,message:a.message,createdAt:a.createdAt,
   finishedAt:a.finishedAt||null,configurationPosts:a.configurationPosts??null,target:a.target}:null;
 const modeMatches=(m,t,route)=>/^[0-3]$/.test(route)&&m?.route===route&&
   m.automatic===t.automatic&&(t.automatic||
   m.primary===t.primary&&m.secondary===t.secondary);
 async function finishMode(a,status,message,configurationPosts,diagnostic=null){
  const result={version:1,id:a.id,status,createdAt:a.createdAt,finishedAt:iso(),
    configurationPosts,message,...(diagnostic?{diagnostic}:{})};
  await replaceAtomic(path.join(modeFolder,a.id,'result.json'),result);
  Object.assign(a,result);
 }
 const dnsUncertain=()=>reconciliation.hasOpen()||modeOpen();
 const publicAttempt=x=>x?reconciliation.publicAttempt({
   id:x.id,status:x.status,phase:x.phase,message:x.message,
   createdAt:x.createdAt,finishedAt:x.finishedAt||null,
   configurationPosts:x.configurationPosts??null,target:x.target||null}):null;
 const pathOf=id=>path.join(folder,id);
 const sanitizedTransport=(outcome,readbackMatched)=>({
   // Durable diagnostic metadata only: no raw body, IPs, cookies or tokens.
   httpStatus:Number.isInteger(outcome?.response?.status)&&
     outcome.response.status>=100&&outcome.response.status<=599?
     outcome.response.status:null,
   transportError:typeof outcome?.response?.transportError==='boolean'?
     outcome.response.transportError:null,
   nativeForm:outcome?.response?.nativeForm===true,
   independentReadback:readbackMatched!==null,
   readbackMatched
 });
 async function finish(a,status,message,configurationPosts,diagnostic=null){
  const result={version:1,id:a.id,status,phase:status==='reviewRequired'?'uncertain':'complete',
    createdAt:a.createdAt,finishedAt:iso(),configurationPosts,message,
    ...(diagnostic?{diagnostic}:{})};
  await replaceAtomic(path.join(pathOf(a.id),'result.json'),result);
  Object.assign(a,result);
 }
 async function handle(req,res,route){
  if(!route.startsWith('/api/dns'))return false;
  if(!['/api/dns','/api/dns/status','/api/dns/mode','/api/dns/mode/prepare','/api/dns/mode/commit','/api/dns/diagnostics','/api/dns/prepare','/api/dns/commit',
    '/api/dns/reconcile','/api/dns/reconcile/inspect',
    '/api/dns/reconcile/acknowledge','/api/dns/relay-diagnostics'].includes(route))
    throw fault('NOT_FOUND',404);
  const session=requireSession(req,true);
  if(route.startsWith('/api/dns/reconcile'))
    return reconciliation.handle(req,res,route,session);
  if(route==='/api/dns/status'&&req.method==='GET'){
    await reconciliation.verifyClosures();
    json(res,200,{latest:publicAttempt(latest()),modeLatest:publicMode(modeLatest()),
      reviewRequired:dnsUncertain(),reconciliation:reconciliation.getStatus()});return true;
  }
  if(route==='/api/dns/diagnostics'&&req.method==='GET'){
    json(res,200,{last:lastDiagnostic});return true;
  }
  if(route==='/api/dns/relay-diagnostics'&&req.method==='GET'){
    if(typeof driver.readDns!=='function')throw fault('DNS_UNAVAILABLE',503);
    let inspected;
    try{
      inspected=await routerWork('dns-relay-diagnostics',async signal=>{
        // The CGI read and DNS fingerprint are independent, read-only
        // operations. Neither can reserve or dispatch DNS_CONF.
        const native=typeof driver.readDnsInventory==='function'?
          await driver.readDnsInventory(session.password,{signal}):
          await driver.readDns(session.password,{signal});
        signal?.throwIfAborted();
        const proxy=await relayProbe({routerIp:getRouterIp()});
        signal?.throwIfAborted();
        if(!proxy||proxy.schema!==1||
          !['RECURSIVE_EGRESS_OBSERVED','INDETERMINATE'].includes(proxy.classification)||
          !proxy.relay||!proxy.cloudflareReference||proxy.nativeDnsConfigPosts!==0)
          throw fault('DNS_RELAY_UNAVAILABLE',502);
        const source=native.nativeDnsInventory;
        const inventory=source?.status==='INSPECTED'&&Array.isArray(source.groups)?
          describeNativeDnsInventory({
            names:source.groups.flatMap(g=>Array.isArray(g?.names)?g.names:[]),
            totalConfigFields:source.totalConfigFields,
            matchingFields:source.matchingFields,
            truncated:source.complete!==true,
            observedValues:source.observedValues
          }):describeNativeDnsInventory({
            names:native.nativeRelatedFields||[],
            matchingFields:Array.isArray(native.nativeRelatedFields)?
              native.nativeRelatedFields.length:0,
            totalConfigFields:null,observedValues:[]
          });
        if(inventory.status!=='INSPECTED'||
          typeof native.primary!=='string'||typeof native.secondary!=='string')
          throw fault('DNS_SCHEMA',502);
        return {wan:{primary:native.primary,secondary:native.secondary},
          inventory,relay:proxy};
      },req);
      assertCurrentSession(session,true);
    }catch(error){
      if(error?.code==='DNS_RELAY_UNAVAILABLE')throw error;
      throw fault('DNS_RELAY_UNAVAILABLE',502);
    }
    // WAN settings and the observed LAN proxy are independent facts. Do not
    // condition a generic diagnostic on the DNS pair used in one test setup.
    json(res,200,{schema:1,checkedAt:iso(),wan:inspected.wan,
      nativeRelatedFields:inspected.inventory.groups.flatMap(g=>g.names),
      dnsInventory:inspected.inventory,
      proxy:inspected.relay,configurationPosts:0,
      status:inspected.relay.classification==='RECURSIVE_EGRESS_OBSERVED'?
        'RECURSIVE_EGRESS_OBSERVED':'RELAY_INDETERMINATE',
      note:'Las DNS WAN configuradas y los resolutores observados desde el proxy de la LAN son datos distintos. No se acredita una relación causal, ni persistencia tras reiniciar.'});
    return true;
  }
  if(route==='/api/dns'&&req.method==='GET'){
    if(typeof driver.readDns!=='function')throw fault('DNS_UNAVAILABLE',503);
    let current;
    try{
      current=await routerWork('dns-read',signal=>
        driver.readDns(session.password,{signal}),req);
      assertCurrentSession(session,true);
      await recordDiagnostic('read','OK');
    }catch(error){
      await recordDiagnostic('read',error?.code);
      throw error;
    }
    json(res,200,{primary:current.primary,secondary:current.secondary,
      automatic:current.automatic,revision:current.revision,readAt:iso(),
      note:'DNS WAN del propio Livebox; podrían restaurarse tras reiniciar.'});return true;
  }
  if(route==='/api/dns/mode'&&req.method==='GET'){
    if(typeof driver.readDnsMode!=='function')throw fault('DNS_UNAVAILABLE',503);
    const mode=await routerWork('dns-mode-read',signal=>driver.readDnsMode(session.password,{signal}),req);
    assertCurrentSession(session,true);
    // Read-only closure of an uncertain attempt: only an observed target
    // state proves the effect, so nothing ever needs to be resent.
    for(const a of modeAttempts.values())
      if(a.status==='reviewRequired'&&a.configurationPosts===1&&
         a.target&&modeMatches(mode,a.target,a.profileRoute))
        await finishMode(a,'succeeded','Valores del mismo perfil DNS releídos posteriormente; no acredita uso WAN ni persistencia.',a.configurationPosts);
    json(res,200,{automatic:mode.automatic,primary:mode.primary,secondary:mode.secondary,
      wan:mode.wan,revision:mode.revision,readAt:iso(),reviewRequired:dnsUncertain(),
      note:mode.automatic?'DNS automáticas: el operador puede reescribirlas al reconectar la WAN.':
        'Valores DNS estáticos leídos de la configuración del Livebox; no demuestra uso WAN ni persistencia.'});
    return true;
  }
  if(route==='/api/dns/mode/prepare'&&req.method==='POST'){
    const body=await bodyOf(req);
    const target=validateDnsModeTarget(objectBody(body,['automatic'],['primary','secondary']));
    if(!await reconciliation.verifyClosures()||unresolved()||otherReview()||dnsUncertain())
      throw fault('DNS_REVIEW_REQUIRED',409);
    if(typeof driver.prepareDnsMode!=='function')throw fault('DNS_UNAVAILABLE',503);
    const prepared=await routerWork('dns-mode-prepare',signal=>
      driver.prepareDnsMode({password:session.password,target,signal}),req);
    assertCurrentSession(session,true);
    if(!prepared.nativeFormVerified||!/^[a-f0-9]{64}$/.test(prepared.before?.revision)||
      !/^[0-3]$/.test(prepared.before?.route))
      throw fault('DNS_UNAVAILABLE',503);
    const id=randomUUID(),createdAt=iso();
    plans.set(id,{id,kind:'mode',sessionId:session.id,createdAt,expiresAt:Date.now()+planTtlMs,
      before:prepared.before,target});
    json(res,200,{planId:id,kind:'mode',createdAt,expiresAt:new Date(Date.now()+planTtlMs).toISOString(),
      previous:{automatic:prepared.before.automatic,primary:prepared.before.primary,secondary:prepared.before.secondary},
      proposed:target,changedFields:prepared.changedFields,
      warnings:target.automatic?['Volver a automático no restaura por sí solo las DNS originales del operador: el router conserva las DNS WAN guardadas hasta que el operador las renueve.']:
        ['Cambio no soportado oficialmente por el operador.',
         'La persistencia tras reiniciar el Livebox requiere una comprobación aparte.']});
    return true;
  }
  if(route==='/api/dns/mode/commit'&&req.method==='POST'){
    const input=objectBody(await bodyOf(req),['planId','confirm']);
    if(input.confirm!==true||typeof input.planId!=='string'||!uuid.test(input.planId))
      throw fault('DNS_CONFIRMATION',400);
    const plan=plans.get(input.planId);
    if(!plan||plan.kind!=='mode'||plan.sessionId!==session.id)throw fault('PLAN_NOT_FOUND',404);
    if(Date.now()>plan.expiresAt){plans.delete(plan.id);throw fault('PLAN_EXPIRED',410);}
    if(!await reconciliation.verifyClosures()||unresolved()||otherReview()||dnsUncertain())
      throw fault('DNS_REVIEW_REQUIRED',409);
    if(typeof driver.applyDnsMode!=='function'||typeof driver.readDnsMode!=='function')
      throw fault('DNS_UNAVAILABLE',503);
    const answer=await routerWork('dns-mode-change',async signal=>{
      if(!plans.has(plan.id))throw fault('ATTEMPT_CONSUMED',409);
      plans.delete(plan.id);
      const a={id:randomUUID(),kind:'mode',createdAt:iso(),status:'running',target:plan.target,
        beforeRevision:plan.before.revision,profileRoute:plan.before.route,
        configurationPosts:null,message:'Comprobando el estado actual del Livebox.'};
      await fs.mkdir(path.join(modeFolder,a.id),{mode:0o700});
      await writeExclusive(path.join(modeFolder,a.id,'reservation.json'),
        {version:1,id:a.id,planId:plan.id,createdAt:a.createdAt,revision:plan.before.revision,
          profileRoute:plan.before.route,target:plan.target});
      modeAttempts.set(a.id,a);
      let dispatched=false,outcome;
      try{
        outcome=await driver.applyDnsMode({password:session.password,target:plan.target,
          expectedRevision:plan.before.revision,signal,
          beforeDispatch:async proof=>{
            if(dispatched||proof?.beforeRevision!==plan.before.revision)throw fault('STALE_PLAN',409);
            await writeExclusive(path.join(modeFolder,a.id,'dispatch.json'),
              {version:1,id:a.id,createdAt:iso(),revision:proof.beforeRevision,changedFields:proof.changedFields});
            dispatched=true;
          }});
      }catch{}
      if(!dispatched){
        await finishMode(a,'failed','No se ha enviado ningún cambio de modo DNS.',0);
        return publicMode(a);
      }
      // No retries: a second login only for independent verification.
      try{
        const after=await driver.readDnsMode(session.password,{signal});
        const matched=modeMatches(after,plan.target,plan.before.route);
        const success=outcome?.configurationPosts===1&&outcome?.response?.transportError===false&&
          outcome?.response?.status>=200&&outcome?.response?.status<400&&matched;
        await finishMode(a,success?'succeeded':'reviewRequired',success?
          'Valores del perfil DNS releídos tras el envío; no demuestra uso WAN ni persistencia.':
          'El resultado del cambio de modo no se ha podido acreditar. No repitas el envío.',
          outcome?.configurationPosts===1?1:null,sanitizedTransport(outcome,matched));
      }catch{
        await finishMode(a,'reviewRequired',
          'Resultado incierto: no se pudo completar una segunda lectura. No repitas el envío.',null,
          sanitizedTransport(outcome,null));
      }
      return publicMode(a);
    },req);
    assertCurrentSession(session,true);
    json(res,200,{operation:answer,reviewRequired:answer.status==='reviewRequired'});
    return true;
  }
  if(route==='/api/dns/prepare'&&req.method==='POST'){
    const desired=validateDnsPair(objectBody(await bodyOf(req),['primary','secondary']));
    if(!await reconciliation.verifyClosures()||unresolved()||otherReview()||modeOpen())throw fault('DNS_REVIEW_REQUIRED',409);
    if(typeof driver.prepareDns!=='function')throw fault('DNS_UNAVAILABLE',503);
    let prepared;
    try{
      prepared=await routerWork('dns-prepare',signal=>
        driver.prepareDns({password:session.password,...desired,signal}),req);
      assertCurrentSession(session,true);
      if(!prepared.nativeFormVerified||
        !/^[a-f0-9]{64}$/.test(prepared.before?.revision))
        throw fault('DNS_UNAVAILABLE',503);
      await recordDiagnostic('prepare','OK');
    }catch(error){
      await recordDiagnostic('prepare',error?.code);
      throw error;
    }
    const id=randomUUID(),createdAt=iso();
    plans.set(id,{id,sessionId:session.id,createdAt,expiresAt:Date.now()+planTtlMs,
      before:prepared.before,target:desired});
    json(res,200,{planId:id,createdAt,expiresAt:new Date(Date.now()+planTtlMs).toISOString(),
      previous:{primary:prepared.before.primary,secondary:prepared.before.secondary},
      proposed:desired,willChange:true,
      warnings:['Cambio no soportado oficialmente por el operador.',
        'Puede revertirse al reiniciar o reprovisionar el router.']});
    return true;
  }
  if(route==='/api/dns/commit'&&req.method==='POST'){
    const input=objectBody(await bodyOf(req),['planId','confirm']);
    if(input.confirm!==true||typeof input.planId!=='string'||!uuid.test(input.planId))
      throw fault('DNS_CONFIRMATION',400);
    const plan=plans.get(input.planId);
    if(!plan||plan.kind==='mode'||plan.sessionId!==session.id)throw fault('PLAN_NOT_FOUND',404);
    if(Date.now()>plan.expiresAt){plans.delete(plan.id);throw fault('PLAN_EXPIRED',410);}
    if(!await reconciliation.verifyClosures()||unresolved()||otherReview()||modeOpen())throw fault('DNS_REVIEW_REQUIRED',409);
    if(typeof driver.applyDns!=='function'||typeof driver.readDns!=='function')
      throw fault('DNS_UNAVAILABLE',503);
    const answer=await routerWork('dns-change',async signal=>{
      // A plan can be consumed once only; claim after acquiring work lock.
      if(!plans.has(plan.id))throw fault('ATTEMPT_CONSUMED',409);
      plans.delete(plan.id);
      const a={id:randomUUID(),planId:plan.id,createdAt:iso(),
        status:'running',phase:'preparing',target:plan.target,
        configurationPosts:null,message:'Comprobando el estado actual del Livebox.'};
      await fs.mkdir(pathOf(a.id),{mode:0o700});
      await writeExclusive(path.join(pathOf(a.id),'reservation.json'),
        {version:1,id:a.id,planId:plan.id,createdAt:a.createdAt,
          revision:plan.before.revision,target:plan.target});
      attempts.set(a.id,a);
      let dispatched=false,outcome;
      try{
        outcome=await driver.applyDns({password:session.password,...plan.target,
          expectedRevision:plan.before.revision,signal,
          beforeDispatch:async proof=>{
            if(dispatched||proof?.beforeRevision!==plan.before.revision||
              proof.before?.primary!==plan.before.primary||
              proof.before?.secondary!==plan.before.secondary)throw fault('STALE_PLAN',409);
            await writeExclusive(path.join(pathOf(a.id),'dispatch.json'),
              {version:1,id:a.id,createdAt:iso(),revision:proof.beforeRevision});
            dispatched=true;a.phase='dispatching';
          }});
      }catch(error){
        if(!dispatched){
          await finish(a,'failed','No se ha enviado ninguna modificación DNS.',0);
          return publicAttempt(a);
        }
      }
      if(!dispatched){
        await finish(a,'failed','No se ha enviado ninguna modificación DNS.',0);
        return publicAttempt(a);
      }
      // No retries: a second login only for independent verification.
      try{
        const after=await driver.readDns(session.password,{signal});
        const readbackMatched=after.primary===plan.target.primary&&
          after.secondary===plan.target.secondary;
        const success=outcome?.configurationPosts===1&&
          outcome?.response?.transportError===false&&
          outcome?.response?.status>=200&&outcome?.response?.status<400&&
          readbackMatched;
        await finish(a,success?'succeeded':'reviewRequired',success?
          'DNS del Livebox verificadas mediante una lectura independiente.':
          'El resultado de la modificación no se ha podido acreditar. No repitas el envío.',
          outcome?.configurationPosts===1?1:null,
          sanitizedTransport(outcome,readbackMatched));
      }catch{
        await finish(a,'reviewRequired',
          'Resultado incierto: no se pudo completar una segunda lectura. No repitas el envío.',null,
          sanitizedTransport(outcome,null));
      }
      return publicAttempt(a);
    },req);
    assertCurrentSession(session,true);
    json(res,200,{operation:answer,reviewRequired:answer.status==='reviewRequired'});
    return true;
  }
  throw fault('METHOD_NOT_ALLOWED',405);
 }
 return {handle,dnsUncertain};
}

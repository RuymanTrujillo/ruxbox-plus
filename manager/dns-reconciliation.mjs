import fs from 'node:fs/promises';
import path from 'node:path';
import {createHash,randomUUID} from 'node:crypto';

const sha = data => createHash('sha256').update(data).digest('hex');
const uuid = /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/;
const hash64 = /^[a-f0-9]{64}$/;
const age = date => Date.now()-Date.parse(date);
const iso = () => new Date().toISOString();
const acknowledgement = 'CONFIRMAR_SIN_EFECTO_PERSISTENTE';
const fail = (code,status=409) => Object.assign(new Error(code),{code,status});
const immutableJson = async (file,obj) => {
 const handle = await fs.open(file,'wx',0o600);
 try {await handle.writeFile(JSON.stringify(obj,null,2)+'\n','utf8');await handle.sync();}
 finally {await handle.close();}
};
const readBounded = async filename => {
 let data;
 try{data=await fs.readFile(filename);}
 catch{throw fail('DNS_RECONCILE_INTEGRITY');}
 if(data.length===0||data.length>8192)throw fail('DNS_RECONCILE_INTEGRITY');
 return data;
};
const parse = data => {
 try {return JSON.parse(data.toString('utf8'));}
 catch {throw fail('DNS_RECONCILE_INTEGRITY');}
};
const readCanonical = async file => {
 const bytes=await readBounded(file),value=parse(bytes);
 if(bytes.toString('utf8')!==JSON.stringify(value,null,2)+'\n')
   throw fail('DNS_RECONCILE_INTEGRITY');
 return {value,bytes};
};
const sameHashes = (a,b) => !!a&&!!b&&
 ['reservation','dispatch','result'].every(k=>hash64.test(a[k]||'')&&a[k]===b[k]);
const validRead = x => x && hash64.test(x.revision||'') &&
 typeof x.primary==='string' && typeof x.secondary==='string' &&
 /^[0-9.]+$/.test(x.primary) && /^[0-9.]+$/.test(x.secondary) &&
 x.primary.length<=15 && x.secondary.length<=15;
const statusOptions = new Set(['ORIGINAL_STATE_OBSERVED_TWICE',
 'TARGET_STATE_OBSERVED_TWICE','OTHER_OR_INCONSISTENT_STATE']);
const equalPair = (a,b) => a.primary===b.primary&&a.secondary===b.secondary;

// An isolated, bounded, append-only reconciliation journal. No router mutations.
// A closure only removes the write lock on a previous unknown attempt; it never
// marks that historical POST as succeeded or proves there was no transient effect.
export async function createDnsReconciliation({
 dataDir,attempts,driver,routerWork,assertCurrentSession,json,bodyOf,
 objectBody,fault,inspectionDelayMs=1200,proofTtlMs=120000
}){
 if(!dataDir||!attempts||!driver||
    !Number.isInteger(inspectionDelayMs)||inspectionDelayMs<0||
    inspectionDelayMs>30000||!Number.isInteger(proofTtlMs)||proofTtlMs<1000)
   throw Error('INVALID_DNS_RECONCILIATION');
 const root=path.join(dataDir,'dns-reconciliations');
 const source=path.join(dataDir,'dns-operations');
 const closures=new Map();
 const inspections=new Map();
 const origin=()=>typeof driver.origin==='string'?driver.origin:null;
 const hasOpen=()=>[...attempts.values()].some(a=>
   (a.status==='reviewRequired'||a.status==='running')&&!closures.has(a.id));
 const pending=()=>[...attempts.values()].filter(a=>a.status==='reviewRequired'&&!closures.has(a.id));
 const opDir=id=>path.join(source,id);
 const recDir=id=>path.join(root,id);
 const inspectionFile=(id,evidenceId)=>path.join(recDir(id),evidenceId+'.json');
 const closureFile=id=>path.join(recDir(id),'closure.json');
 const snapshot=async id=>{
   if(!uuid.test(id)||!attempts.has(id))throw fail('DNS_RECONCILE_INTEGRITY');
   const dir=opDir(id), hashes={},raw={};
   for(const name of ['reservation','dispatch','result']){
     raw[name]=await readBounded(path.join(dir,name+'.json'));
     hashes[name]=sha(raw[name]);
   }
   const reservation=parse(raw.reservation),dispatch=parse(raw.dispatch),
     result=parse(raw.result);
   if(reservation.version!==1||reservation.id!==id||!hash64.test(reservation.revision)||
     !reservation.target||typeof reservation.target!=='object'||
     !Object.keys(reservation.target).sort().join(',').match(/^primary,secondary$/)||
     dispatch.version!==1||dispatch.id!==id||
     dispatch.revision!==reservation.revision||
     result.version!==1||result.id!==id||result.status!=='reviewRequired'||
     result.configurationPosts!==1||
     !Number.isFinite(Date.parse(result.finishedAt))||
     !Number.isFinite(Date.parse(reservation.createdAt))||
     result.finishedAt<reservation.createdAt)
     throw fail('DNS_RECONCILE_INTEGRITY');
   for(const field of ['primary','secondary']){
     if(typeof reservation.target[field]!=='string'||
        !/^[0-9.]{7,15}$/.test(reservation.target[field]))
       throw fail('DNS_RECONCILE_INTEGRITY');
   }
   return {id,hashes,revision:reservation.revision,target:reservation.target,
     createdAt:reservation.createdAt,finishedAt:result.finishedAt};
 };
 const readEvidence=async(id,evidenceId,base)=>{
   if(!uuid.test(id)||!uuid.test(evidenceId))throw fail('DNS_RECONCILE_INTEGRITY');
   const {value,bytes:buffer}=await readCanonical(inspectionFile(id,evidenceId));
   if(value.schema!==1||value.id!==evidenceId||value.operationId!==id||
     !sameHashes(value.originalHashes,base.hashes)||
     !statusOptions.has(value.classification)||
     !Number.isFinite(Date.parse(value.createdAt))||
     !Array.isArray(value.observations)||value.observations.length!==2||
     !value.observations.every(x=>hash64.test(x.revision||'')&&
       typeof x.matchesOriginal==='boolean'&&typeof x.matchesTarget==='boolean')||
     typeof value.routerOrigin!=='string'&&value.routerOrigin!==null||
     value.routerOrigin!==origin()||
     value.configurationPosts!==0)
     throw fail('DNS_RECONCILE_INTEGRITY');
   const originalBoth=value.observations.every(x=>x.matchesOriginal &&
      x.revision===base.revision&&!x.matchesTarget);
   if((value.classification==='ORIGINAL_STATE_OBSERVED_TWICE')!==originalBoth)
     throw fail('DNS_RECONCILE_INTEGRITY');
   return {value,hash:sha(buffer)};
 };
 const readClosure=async(id,base)=>{
   const {value}=await readCanonical(closureFile(id));
   if(value.schema!==1||value.operationId!==id||
     !uuid.test(value.evidenceId||'')||!hash64.test(value.evidenceSha256||'')||
     !sameHashes(value.originalHashes,base.hashes)||
     value.confirmation!==acknowledgement||
     value.closeReadRevision!==base.revision||
     value.routerOrigin!==origin()||
     !Number.isFinite(Date.parse(value.closedAt)))throw fail('DNS_RECONCILE_INTEGRITY');
   const evidence=await readEvidence(id,value.evidenceId,base);
   if(evidence.hash!==value.evidenceSha256||
     evidence.value.classification!=='ORIGINAL_STATE_OBSERVED_TWICE'||
     Date.parse(value.closedAt)<Date.parse(evidence.value.createdAt))
     throw fail('DNS_RECONCILE_INTEGRITY');
   return value;
 };
 for(const attempt of attempts.values()){
   if(attempt.status!=='reviewRequired')continue;
   try {
     const base=await snapshot(attempt.id);
     const closed=await readClosure(attempt.id,base);
     closures.set(attempt.id,closed);
   }catch{}
   try{
     const entries=await fs.readdir(recDir(attempt.id));
     if(entries.length>150)continue;
     for(const filename of entries.filter(x=>uuid.test(x.replace(/\.json$/,''))&&x.endsWith('.json'))){
       try{
         const base=await snapshot(attempt.id);
         const proof=await readEvidence(attempt.id,filename.slice(0,-5),base);
         const prev=inspections.get(attempt.id);
         if(!prev||proof.value.createdAt>prev.value.createdAt)
           inspections.set(attempt.id,proof);
       }catch{}
     }
   }catch{}
 }
 const effectiveStatus=a=>closures.has(a.id)?'resolvedNoPersistentEffect':a.status;
 const publicAttempt=a=>a?{...a,status:effectiveStatus(a),
   originalStatus:a.status,closedAt:closures.get(a.id)?.closedAt||null}:null;
 const inspectionPublic=p=>p?({
   evidenceId:p.value.id,operationId:p.value.operationId,
   classification:p.value.classification,createdAt:p.value.createdAt,
   expiresAt:new Date(Date.parse(p.value.createdAt)+proofTtlMs).toISOString(),
   canAcknowledge:p.value.classification==='ORIGINAL_STATE_OBSERVED_TWICE'&&
     age(p.value.createdAt)>=0&&age(p.value.createdAt)<=proofTtlMs
 }):null;
 const getStatus=()=>{
   const unresolved=pending();
   const attempt=unresolved.length===1?unresolved[0]:null;
   return {reviewRequired:hasOpen(),pendingCount:unresolved.length,
     operationId:attempt?.id||null,latest:attempt?inspectionPublic(inspections.get(attempt.id)):null,
     closure:[...closures.entries()].map(([id,c])=>({operationId:id,closedAt:c.closedAt})),
     note:'La conciliación solo observa el estado actual; no demuestra que no hubiera cambios transitorios.'};
 };
 const verifyClosures=async()=>{
   let valid=true;
   for(const [id] of closures){
     try{await readClosure(id,await snapshot(id));}
     catch{
       // If an on-disk closure is altered while the server is running, re-lock
       // immediately instead of trusting a stale in-memory success.
       closures.delete(id);
       valid=false;
     }
   }
   return valid&&!hasOpen();
 };
 const choose=()=>{
   const matches=pending();
   if(matches.length!==1||hasOpen()!==true)throw fault('DNS_RECONCILE_NOT_ELIGIBLE',409);
   // A malformed/running journal must never be dismissed as a completed operation.
   if([...attempts.values()].some(x=>x.status==='running'))throw fault('DNS_RECONCILE_NOT_ELIGIBLE',409);
   return matches[0];
 };
 const inspect=async(req,session)=>{
   const attempt=choose();
   if(typeof driver.readDns!=='function')throw fault('DNS_RECONCILE_READ_FAILED',503);
   const base=await snapshot(attempt.id);
   let observations;
   try{
     observations=await routerWork('dns-reconcile-read',async signal=>{
       const first=await driver.readDns(session.password,{signal});
       signal?.throwIfAborted();
       if(inspectionDelayMs)await new Promise(resolve=>setTimeout(resolve,inspectionDelayMs));
       signal?.throwIfAborted();
       const second=await driver.readDns(session.password,{signal});
       signal?.throwIfAborted();
       return [first,second];
     },req);
     assertCurrentSession(session,true);
   }catch{throw fault('DNS_RECONCILE_READ_FAILED',502);}
   if(!Array.isArray(observations)||observations.length!==2||
      observations.some(x=>!validRead(x)))
     throw fault('DNS_RECONCILE_READ_FAILED',502);
   const current=await snapshot(attempt.id);
   if(!sameHashes(base.hashes,current.hashes))throw fault('DNS_RECONCILE_INTEGRITY',409);
   const bothOriginal=observations.every(x=>x.revision===base.revision&&!equalPair(x,base.target));
   const bothTarget=observations.every(x=>equalPair(x,base.target));
   const classification=bothOriginal?'ORIGINAL_STATE_OBSERVED_TWICE':
     bothTarget?'TARGET_STATE_OBSERVED_TWICE':'OTHER_OR_INCONSISTENT_STATE';
   const id=randomUUID();
   const record={schema:1,id,operationId:attempt.id,createdAt:iso(),
     routerOrigin:origin(),originalHashes:base.hashes,
     classification,configurationPosts:0,
     observations:observations.map(x=>({revision:x.revision,
       matchesOriginal:x.revision===base.revision,
       matchesTarget:equalPair(x,base.target)}))};
   await fs.mkdir(recDir(attempt.id),{recursive:true,mode:0o700});
   await immutableJson(inspectionFile(attempt.id,id),record);
   const proof=await readEvidence(attempt.id,id,base);
   inspections.set(attempt.id,proof);
   return {status:'INSPECTED_READ_ONLY',evidence:inspectionPublic(proof),
     reviewRequired:true,writePosts:0};
 };
 const acknowledge=async(req,session,input)=>{
   if(!input||typeof input.operationId!=='string'||typeof input.evidenceId!=='string'||
      input.confirm!==acknowledgement)throw fault('DNS_RECONCILE_CONFIRMATION',400);
   const a=choose();
   if(typeof driver.readDns!=='function')throw fault('DNS_RECONCILE_READ_FAILED',503);
   if(input.operationId!==a.id)throw fault('DNS_RECONCILE_INTEGRITY',409);
   const before=await snapshot(a.id);
   const evidence=await readEvidence(a.id,input.evidenceId,before);
   if(evidence.value.classification!=='ORIGINAL_STATE_OBSERVED_TWICE'||
      age(evidence.value.createdAt)<0||age(evidence.value.createdAt)>proofTtlMs)
     throw fault('DNS_RECONCILE_EXPIRED',409);
   if(closures.has(a.id))throw fault('DNS_RECONCILE_INTEGRITY',409);
   return routerWork('dns-reconcile-close',async signal=>{
     const current=await driver.readDns(session.password,{signal});
     signal?.throwIfAborted();assertCurrentSession(session,true);
     if(!validRead(current)||current.revision!==before.revision||
       equalPair(current,before.target))throw fault('DNS_RECONCILE_CHANGED',409);
     const after=await snapshot(a.id);
     if(!sameHashes(before.hashes,after.hashes)||
       age(evidence.value.createdAt)<0||age(evidence.value.createdAt)>proofTtlMs)
       throw fault('DNS_RECONCILE_EXPIRED',409);
     const closure={schema:1,operationId:a.id,evidenceId:input.evidenceId,
       evidenceSha256:evidence.hash,originalHashes:before.hashes,
       confirmation:acknowledgement,routerOrigin:origin(),
       closeReadRevision:current.revision,closedAt:iso(),
       note:'Reconocido solo que el estado previo vuelve a estar presente; no prueba ausencia de efectos transitorios.'};
     // The one-time acknowledgement is durable and leaves the original 3 files intact.
     await immutableJson(closureFile(a.id),closure);
     await readClosure(a.id,before);
     closures.set(a.id,closure);
     return {status:'RESOLVED_NO_PERSISTENT_EFFECT',closedAt:closure.closedAt,
       originalStatus:'reviewRequired',reviewRequired:hasOpen(),
       configurationPosts:0,note:closure.note};
   },req);
 };
 async function handle(req,res,route,session){
   if(!route.startsWith('/api/dns/reconcile'))return false;
   if(route==='/api/dns/reconcile'&&req.method==='GET'){
     await verifyClosures();
     json(res,200,getStatus());return true;
   }
   if(route==='/api/dns/reconcile/inspect'&&req.method==='POST'){
     objectBody(await bodyOf(req),[]);
     json(res,200,await inspect(req,session));return true;
   }
   if(route==='/api/dns/reconcile/acknowledge'&&req.method==='POST'){
     const input=objectBody(await bodyOf(req),
       ['operationId','evidenceId','confirm']);
     json(res,200,await acknowledge(req,session,input));return true;
   }
   throw fault('METHOD_NOT_ALLOWED',405);
 }
 return {handle,hasOpen,isClosed:id=>closures.has(id),publicAttempt,getStatus,verifyClosures};
}

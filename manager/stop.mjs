// RuxBox+ local authenticated and non-destructive shutdown client.
import http from 'node:http';
import fs from 'node:fs/promises';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {ensurePrivateDataDir} from './private-storage.mjs';

const here = path.dirname(fileURLToPath(import.meta.url));
const uuid = /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/;

function delay(ms) { return new Promise(resolve => setTimeout(resolve, ms)); }
function call(port, route, method = 'GET', secret = null) {
  return new Promise((resolve, reject) => {
    const headers = {'Connection': 'close'};
    if (method === 'POST') {
      headers['Content-Length'] = '0';
      headers['X-RuxBox-Stop-Secret'] = secret;
    }
    const req = http.request({hostname:'127.0.0.1',port,method,path:route,
      headers,timeout:3000,agent:false}, res => {
      let total = 0, text = '';
      res.setEncoding('utf8');
      res.on('data', chunk => {
        total += Buffer.byteLength(chunk);
        if (total > 8192) { req.destroy(new Error('RESPONSE_TOO_LARGE')); return; }
        text += chunk;
      });
      res.on('end', () => {
        let body = null;
        try { body = JSON.parse(text); } catch {}
        resolve({status:res.statusCode,body});
      });
    });
    req.on('timeout', () => req.destroy(new Error('LOCAL_TIMEOUT')));
    req.on('error', reject);
    req.end();
  });
}
async function probe(port) {
  try { return await call(port,'/api/health'); }
  catch (error) {
    if (['ECONNREFUSED','ECONNRESET','EPIPE'].includes(error?.code)) return null;
    throw error;
  }
}
async function readLock(file) {
  let stat;
  try { stat = await fs.lstat(file); }
  catch (error) { if (error?.code==='ENOENT') return null; throw error; }
  if (!stat.isFile() || stat.isSymbolicLink() || stat.size > 4096 || stat.size < 20)
    throw new Error('LOCK_INVALID');
  let obj;
  try { obj = JSON.parse(await fs.readFile(file,'utf8')); } catch { throw new Error('LOCK_INVALID'); }
  if (!Number.isInteger(obj.pid) || obj.pid<1 || !uuid.test(obj.instanceId) ||
      !Number.isFinite(Date.parse(obj.startedAt)) ||
      typeof obj.stopSecret!=='string' || !/^[a-f0-9]{64}$/.test(obj.stopSecret)) {
    throw new Error('STOP_NOT_SUPPORTED_OR_LOCK_INVALID');
  }
  return obj;
}
export async function stopLocalManager({dataDir=path.join(here,'data'),port=8765,
  waitMs=15000} = {}) {
  if(typeof dataDir!=='string' || !path.isAbsolute(dataDir) ||
     !Number.isInteger(port) || port<1 || port>65535 ||
     !Number.isInteger(waitMs) || waitMs<100 || waitMs>60000)
    throw new Error('OPTIONS_INVALID');
  const lockfile=path.join(dataDir,'instance.lock');
  let st;
  try { st=await fs.lstat(dataDir); }
  catch(error) {
    if(error?.code!=='ENOENT')throw error;
    if(await probe(port))throw new Error('INSTANCE_NOT_OWNED');
    return {status:'ALREADY_STOPPED'};
  }
  if(!st.isDirectory()||st.isSymbolicLink())throw new Error('PRIVATE_DATA_INVALID');
  await ensurePrivateDataDir(dataDir);
  const lock=await readLock(lockfile);
  if(!lock) {
    if(await probe(port))throw new Error('INSTANCE_NOT_OWNED');
    return {status:'ALREADY_STOPPED'};
  }
  const health=await probe(port);
  if(!health || health.status!==200 || health.body?.instanceId!==lock.instanceId ||
     health.body?.product!=='RUX REAROUTER')throw new Error('INSTANCE_NOT_VERIFIED');
  if(health.body.busy!==false)throw new Error('ACTIVE_OPERATION');
  // One request only. Never retry a possibly accepted shutdown.
  const result=await call(port,'/api/internal/stop','POST',lock.stopSecret);
  if(result.status!==202 || result.body?.status!=='STOP_ACCEPTED' ||
     result.body?.instanceId!==lock.instanceId)throw new Error('STOP_REJECTED');
  const until=Date.now()+waitMs;
  while(Date.now()<until) {
    await delay(150);
    const current=await fs.readFile(lockfile,'utf8').then(x=>x,e=>{
      if(e?.code==='ENOENT')return null;
      throw e;
    });
    const endpoint=await probe(port);
    if(current===null && endpoint===null)return {status:'STOPPED'};
    // Stop only this instance. Do not accept a live replacement as stopped.
    if(endpoint?.body?.instanceId && endpoint.body.instanceId!==lock.instanceId)
      throw new Error('INSTANCE_REPLACED');
  }
  throw new Error('STOP_UNVERIFIED');
}
if (process.argv[1] && path.resolve(process.argv[1])===fileURLToPath(import.meta.url)) {
  try {
    const status=await stopLocalManager();
    console.log(status.status==='STOPPED'
      ? 'RuxBox+ detenido: puerto liberado y bloqueo de instancia retirado.'
      : 'RuxBox+ ya estaba detenido.');
  } catch {
    console.error('No se pudo acreditar una parada segura. No se han forzado procesos ni borrado bloqueos.');
    process.exitCode=1;
  }
}

import fs from 'node:fs/promises';
import path from 'node:path';
import {randomUUID} from 'node:crypto';
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';

export const DEFAULT_ROUTER_IP = '192.168.1.1';
const runFile = promisify(execFile);
function invalid(code) { throw Object.assign(new Error(code), {code}); }
export function validateRouterIp(value) {
  if (typeof value !== 'string' || !/^(?:0|[1-9][0-9]{0,2})(?:\.(?:0|[1-9][0-9]{0,2})){3}$/.test(value)) invalid('INVALID_ROUTER_IP');
  const parts = value.split('.').map(Number);
  if (parts.some(n => n > 255) || !(parts[0] === 10 || (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) || (parts[0] === 192 && parts[1] === 168))) invalid('INVALID_ROUTER_IP');
  return value;
}
export function routerOrigin(ip) { return 'http://' + validateRouterIp(ip); }
export async function createRouterSettings(dataDir) {
  const file = path.join(dataDir, 'settings.json');
  let current = {version:1, routerIp:DEFAULT_ROUTER_IP};
  try {
    const bytes = await fs.readFile(file);
    if (bytes.length > 4096) invalid('SETTINGS_INVALID');
    const read = JSON.parse(bytes.toString('utf8'));
    if (!read || read.version !== 1 || Object.keys(read).some(k=>!['version','routerIp'].includes(k))) invalid('SETTINGS_INVALID');
    current = {version:1, routerIp:validateRouterIp(read.routerIp)};
  } catch(error) { if (error.code !== 'ENOENT') invalid('SETTINGS_INVALID'); }
  return {
    get:()=>({...current}),
    async save(ip) {
      const next = {version:1, routerIp:validateRouterIp(ip)};
      const tmp = file + '.' + randomUUID() + '.tmp';
      let handle;
      try {
        handle = await fs.open(tmp,'wx',0o600);
        await handle.writeFile(JSON.stringify(next,null,2)+'\n','utf8');
        await handle.sync(); await handle.close(); handle=null;
        await fs.rename(tmp,file); current=next;
      } catch { if(handle) await handle.close().catch(()=>{}); await fs.unlink(tmp).catch(()=>{}); invalid('LOCAL_STORAGE'); }
      return {...current};
    }
  };
}
export function selectGatewayCandidates(records) {
  const unique = new Map();
  if (!Array.isArray(records) || records.length > 256) invalid('GATEWAY_UNAVAILABLE');
  for(const record of records) {
    if (!record || typeof record !== 'object') continue;
    let ip; try { ip=validateRouterIp(record.ip); } catch { continue; }
    const metric=Number(record.metric);
    if (!Number.isFinite(metric) || metric < 0) continue;
    const entry={ip,metric,interface:String(record.interface||'Interfaz de red').slice(0,100)};
    if (!unique.has(ip) || unique.get(ip).metric>metric) unique.set(ip,entry);
  }
  return [...unique.values()].sort((a,b)=>a.metric-b.metric || a.ip.localeCompare(b.ip)).slice(0,12);
}
export async function detectRouterGateway() {
  // Read the local routing table. No subnet scan, HTTP probe, login or router write.
  if(process.platform !== 'win32') invalid('GATEWAY_UNAVAILABLE');
  const executable=path.join(process.env.SystemRoot || 'C:\\Windows','System32','WindowsPowerShell','v1.0','powershell.exe');
  const command="$ErrorActionPreference='Stop';$OutputEncoding=[Console]::OutputEncoding=[System.Text.UTF8Encoding]::new($false);$ifs=Get-NetIPInterface -AddressFamily IPv4|Where-Object {$_.ConnectionState -eq 'Connected'};$list=@(Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0'|ForEach-Object {$r=$_;$i=$ifs|Where-Object {$_.InterfaceIndex -eq $r.InterfaceIndex}|Select-Object -First 1;if($i -and $r.NextHop -ne '0.0.0.0'){[pscustomobject]@{ip=$r.NextHop;metric=($r.RouteMetric+$i.InterfaceMetric);interface=$r.InterfaceAlias}}});ConvertTo-Json -InputObject $list -Compress";
  try {
    const {stdout}=await runFile(executable,['-NoProfile','-NonInteractive','-Command',command],{timeout:8000,maxBuffer:65536,windowsHide:true,encoding:'utf8'});
    const candidates=selectGatewayCandidates(JSON.parse(stdout.replace(/^\uFEFF/,'')));
    return {candidates,routerIp:candidates[0]?.ip || null,method:'local-default-ipv4-route',verifiedLivebox:false};
  } catch { invalid('GATEWAY_UNAVAILABLE'); }
}

import fs from 'node:fs';
import path from 'node:path';

const win = path.win32;
const error = () => Object.assign(
  new Error('No se ha encontrado un navegador Chromium compatible. Instala Chrome, Brave o Edge o define REAROUTER_CHROME con una ruta absoluta.'),
  {code:'BROWSER_UNAVAILABLE'}
);

const appPaths = [
  ['Google','Chrome','Application','chrome.exe'],
  ['BraveSoftware','Brave-Browser','Application','brave.exe'],
  ['Microsoft','Edge','Application','msedge.exe'],
];

// Browser installation directories are OS conventions, not machine-specific
// project configuration. The first available executable is used; no shell,
// registry editing, network install, browser profile or user credentials.
export function browserCandidates({env=process.env,platform=process.platform}={}) {
  if(platform!=='win32')return [];
  const explicit=env.REAROUTER_CHROME;
  if(explicit!==undefined && explicit!=='') {
    if(typeof explicit!=='string'||!win.isAbsolute(explicit)||
       !/\.exe$/i.test(explicit))throw error();
    return [win.normalize(explicit)];
  }
  const roots=[env.ProgramFiles,env['ProgramFiles(x86)'],env.ProgramW6432,
    env.LOCALAPPDATA];
  const paths=[];
  for(const components of appPaths){
    for(const root of roots){
      if(typeof root!=='string'||!win.isAbsolute(root))continue;
      paths.push(win.join(root,...components));
    }
  }
  const unique=new Set();
  return paths.filter(p=>{
    const key=p.toLowerCase();
    if(unique.has(key))return false;
    unique.add(key);
    return true;
  });
}

export function resolveBrowserExecutable({env=process.env,
  platform=process.platform,exists=path=> {
    try{return fs.statSync(path).isFile();}catch{return false;}
  }}={}) {
  for(const candidate of browserCandidates({env,platform})){
    if(exists(candidate))return candidate;
  }
  throw error();
}

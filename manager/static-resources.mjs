import fs from 'node:fs/promises';
import path from 'node:path';
import {FLAG_ISOS} from './public/call-enrichment.mjs';

// Explicit public allowlist. No directory traversal or private data.
const publicRoutes=new Map([
  ['/','index.html'],['/index.html','index.html'],
  ['/app.js','app.js'],['/app-info.mjs','app-info.mjs'],['/style.css','style.css'],
  ['/policy-batch.mjs','policy-batch.mjs'],
  ['/history-view.mjs','history-view.mjs'],
  ['/call-enrichment.mjs','call-enrichment.mjs'],
  ['/call-monitor.mjs','call-monitor.mjs'],
  ['/dns-ui.mjs','dns-ui.mjs'],
  ['/legacy-readback.mjs','legacy-readback.mjs'],
  ['/call-history-view.mjs','call-history-view.mjs'],
  ['/router-info-dialog.mjs','router-info-dialog.mjs'],
  ['/router-info-model.mjs','router-info-model.mjs'],
  ['/request-budget.mjs','request-budget.mjs'],
  ['/theme.js','theme.js'],
  ['/ruxbox-plus-logo.png','ruxbox-plus-logo.png'],
  ['/ruxbox-plus-icon.png','ruxbox-plus-icon.png'],
  ['/ruxbox-plus-favicon.png','ruxbox-plus-favicon.png'],
  ['/enhancements.css','enhancements.css']
]);

export function classifyStaticRoute(route,method='GET'){
  if(method!=='GET'||typeof route!=='string')return null;
  const fixed=publicRoutes.get(route);
  if(fixed)return {file:fixed,
    mime:fixed.endsWith('.js')||fixed.endsWith('.mjs')?
      'text/javascript; charset=utf-8':
      fixed.endsWith('.png')?'image/png':
      fixed.endsWith('.css')?'text/css; charset=utf-8':
        'text/html; charset=utf-8',cache:null};
  if(/^\/flags\/[a-z]{2}\.svg$/u.test(route)){
    const iso=route.slice(7,-4);
    if(!FLAG_ISOS.has(iso))return {notFound:true};
    return {file:'flags/'+iso+'.svg',mime:'image/svg+xml; charset=utf-8',
      cache:'public, max-age=86400'};
  }
  return null;
}

export async function serveStaticResource(req,res,route,{publicDir,fault}){
  const resource=classifyStaticRoute(route,req.method);
  if(!resource)return false;
  if(resource.notFound)throw fault('NOT_FOUND',404);
  const content=await fs.readFile(path.join(publicDir,resource.file));
  const headers={'Content-Type':resource.mime};
  if(resource.cache)Object.assign(headers,{
    'Cache-Control':resource.cache,'X-Content-Type-Options':'nosniff'});
  res.writeHead(200,headers);
  res.end(content);
  return true;
}

import fs from 'node:fs/promises';
import path from 'node:path';
import {createHash} from 'node:crypto';
import {fileURLToPath,pathToFileURL} from 'node:url';
import {
  stateHash,
  assertAddPreconditions, assertDeletePreconditions,
} from './core.mjs';
import {createFirstCallLogCapture, CALL_HISTORY_LIMITS, validateCallHistory, callHistoryRevision} from './call-history.mjs';
import {routerOrigin, DEFAULT_ROUTER_IP} from './router-settings.mjs';
import {resolveBrowserExecutable} from './browser-runtime.mjs';
import {REQUEST_BUDGETS} from './public/request-budget.mjs';
import {inspectBlockCgi,inspectPhoneCgi,composeCompatibility} from './compatibility.mjs';
import {assertNativeForm,assertNativeClearLogForm,assertNativeRingTestForm} from './native-form.mjs';
import {parseAutodialFields,autoDialChanges,assertNativeAutodialForm} from './autodial-core.mjs';
import {parseRouterDeviceInfo} from './router-device-info.mjs';
import {parseDnsValue,validateDnsPair,dnsRevision,validateDnsNativeForm,
  validateDnsModeTarget,parseDnsMode,dnsModeChanges,validateDnsModeForm} from './dns-core.mjs';
import {describeNativeDnsInventory} from './dns-relay-probe.mjs';
import {identifyRouter,loginLegacyFibra,legacyAutodialSnapshot,legacyAutodialField,hasNativeLegacyClearLog,
  legacyPhoneSettingsRevision} from './legacy-fibra.mjs';
export {assertNativeForm,assertNativeClearLogForm,assertNativeRingTestForm} from './native-form.mjs';

// The configured external VoIP account is the line identity, not the caller
// shown in call logs. Fail closed if the router presents multiple accounts.
export function extractConfiguredFixedLine(phoneFields) {
  if (!Array.isArray(phoneFields)) return null;
  const accounts=phoneFields.filter(entry=>Array.isArray(entry)&&
    /^extacc_user_id_[0-9]$/.test(entry[0])&&typeof entry[2]==='string'&&entry[2]!=='');
  if (accounts.length!==1 || accounts[0][0]!=='extacc_user_id_0') return null;
  const account=accounts[0][2];
  // The native Spanish fixed line uses +34 followed by nine digits beginning 8/9.
  return /^\+34[89][0-9]{8}$/.test(account) ? account : null;
}
export const ROUTER_ORIGIN = 'http://192.168.1.1';
const sha = value => createHash('sha256').update(value).digest('hex');
const MODULE_DIR = path.dirname(fileURLToPath(import.meta.url));
// Only resources observed in authenticated evidence. GET is not blanket permission.
const READ_PATHS = new Set([
  '/index.htm','/login.htm','/phones.htm','/top.htm','/network_connected.htm',
  // Exact read-only dependencies seen in the authenticated index frameset:
  // network_connected.htm loads all three during its asynchronous init.
  '/cgi/cgi_network_connected.js','/cgi/cgi_clients.js','/cgi/cgi_firewall_mac_filter.js',
  '/css/ie.css','/images/favicon.ico',
  '/advanced_network_dns.htm','/advanced_network_configuration.htm','/advanced_network_upnp.htm',
  '/cgi/cgi_dns.js','/cgi/cgi_network_dns.js','/cgi/cgi_network.js',
  '/cgi/cgi_init.js','/cgi/cgi_phones.js','/cgi/cgi_call_log.js','/cgi/cgi_tel_call_blocking.js',
  '/cgi/cgi_router_status.js','/cgi/cgi_info.js',
  '/js/arc-crypt.js','/js/global.js','/js/jquery-3.6.0.min.js','/js/jquery.arctransform.js',
  '/js/maxnum_define.js','/js/menulist.js','/js/osp_menu.js','/js/subformvar.js',
  '/lang/en.js','/lang/en/menulist.js','/lang/sp.js',
  '/css/arctransform.css','/css/osp_reset.css','/css/osp_styles.css',
  '/images/Livebox_6.png','/images/buttons-factory.png','/images/flag-sp.gif',
  '/images/footer-background.png','/images/header-background.png','/images/hmenu_off.png',
  '/images/icons-home.png','/images/icons-leds-green.png','/images/icons-leds-red.png',
  '/images/input-hr-orange.png','/images/livebox_6_login.png',
  '/images/popup-header-close-button.png','/images/vmenu.png',
]);

function fail(code) {
  const error = new Error(code);
  error.code = code;
  throw error;
}
export function makeRevision(snapshot) {
  if (!snapshot?.phone || snapshot.phone.fields !== 78 || typeof snapshot.phone.sha256 !== 'string' ||
      !/^[a-f0-9]{64}$/.test(snapshot.phone.sha256)) fail('PHONE_SCHEMA');
  return sha(JSON.stringify([stateHash(snapshot.rows),snapshot.phone.sha256]));
}

export function allowRouterRequest(request, permit, usedCount, loginCount, origin = ROUTER_ORIGIN) {
  if (request.origin !== origin || request.credentials) return false;
  if (['GET','HEAD'].includes(request.method)) return READ_PATHS.has(request.path);
  if (request.method !== 'POST' || request.search !== '') return false;
  if (request.path === '/login.cgi') return loginCount === 0 && !permit;
  return request.path === '/apply_abstract.cgi' && usedCount === 0 &&
    !!permit && typeof permit.body === 'string' && permit.body.length > 0 &&
    request.body === permit.body && ['add','delete','clear-history','ring-test','autodial','dns','dns-mode'].includes(permit.type);
}


/** The intercepted browser GET is forwarded once, with a bounded streaming body.
 * No received JavaScript is evaluated, no redirect is followed and no retry exists.
 * fetchImpl is injectable only for offline transport tests.
 */
export async function readBoundedCallLog({url, origin, headers, signal, fetchImpl = fetch}) {
  const target = new URL(url);
  if (target.origin !== origin || target.pathname !== '/cgi/cgi_call_log.js' || target.username || target.password) fail('CALL_LOG_SCHEMA');
  const response = await fetchImpl(target.href, {method:'GET', headers:{...headers,'accept-encoding':'identity'}, redirect:'error', signal});
  if (response.status === 401 || response.status === 403) { await response.body?.cancel(); fail('AUTH_FAILED'); }
  if (response.status !== 200 || !response.body) { await response.body?.cancel(); fail('READ_UNAVAILABLE'); }
  const maximum = CALL_HISTORY_LIMITS.maxJavascriptBytes;
  const declared = response.headers.get('content-length');
  if (declared !== null && /^\d+$/.test(declared) && Number(declared) > maximum) { await response.body.cancel(); fail('CALL_LOG_TOO_LARGE'); }
  const reader = response.body.getReader(), chunks = []; let bytes = 0;
  try {
    for (;;) {
      signal?.throwIfAborted();
      const item = await reader.read(); if (item.done) break;
      bytes += item.value.byteLength;
      if (bytes > maximum) { await reader.cancel(); fail('CALL_LOG_TOO_LARGE'); }
      chunks.push(item.value);
    }
  } finally { reader.releaseLock(); }
  const data = Buffer.concat(chunks, bytes);
  let body; try { body = new TextDecoder('utf-8', {fatal:true}).decode(data); } catch { fail('CALL_LOG_SCHEMA'); }
  return {status:response.status, body};
}

/** Fresh isolated browser per read or write. No persistent authentication or raw captures. */
export class LiveboxDriver {
  constructor({root=path.resolve(MODULE_DIR,'..'), executablePath=null}={}) {
    this.origin=routerOrigin(DEFAULT_ROUTER_IP);
    this.root=root;
    this.executablePath=executablePath===null?
      resolveBrowserExecutable():resolveBrowserExecutable({env:{REAROUTER_CHROME:executablePath}});
  }
  setRouterIp(ip) { this.origin=routerOrigin(ip); }
  async identifyProfile({signal}={}){
    return identifyRouter(new URL(this.origin).hostname,{signal});
  }
  async connectLegacy({password,signal,ip,onPhase,inspect,operation}){
    await this.initialize();
    return loginLegacyFibra({
      ip,password,signal,onPhase,inspect,operation,chromium:this.chromium,executablePath:this.executablePath
    });
  }
  // Old-firmware adapter with the modern method signatures; one native
  // login and logout per call, never a retry.
  get legacy(){
    const run=async({password,signal},operation)=>(await this.connectLegacy({
      password,signal,operation,ip:new URL(this.origin).hostname})).operation;
    return {
      readCalls:(password,{signal}={})=>run({password,signal},api=>api.callLog()),
      // Only the firmware-declared ClearLog() action, on the exact history the
      // user confirmed. server.mjs persists its checkpoint before the one POST.
      clearCalls:({password,beforeDispatch,expectedRevision,signal})=>{
        if(typeof beforeDispatch!=='function'||typeof expectedRevision!=='string'||
           !/^[a-f0-9]{64}$/.test(expectedRevision))fail('INVALID_ACTION');
        return run({password,signal},async api=>{
          const before=validateCallHistory(await api.callLog());
          if(before.total===0)fail('CALL_LOG_EMPTY');
          const beforeRevision=callHistoryRevision(before);
          if(beforeRevision!==expectedRevision)fail('CALL_LOG_CHANGED');
          const source=await api.reader.page('/phones.htm');
          if(source.status!==200||!hasNativeLegacyClearLog(source.body))
            fail('LEGACY_CLEAR_UNVERIFIED');
          const config=await api.phoneCfg();
          if(!config.has('clearlog'))fail('LEGACY_CLEAR_UNVERIFIED');
          const settingsRevision=legacyPhoneSettingsRevision(config);
          if(callHistoryRevision(validateCallHistory(await api.callLog()))!==beforeRevision)
            fail('CALL_LOG_CHANGED');
          const result=await api.nativeApply([['clearlog','1']],
            ()=>beforeDispatch({beforeRevision,observedCount:before.total,settingsRevision}));
          return {...result,beforeRevision,settingsRevision};
        });
      },
      // Independent post-check: its own native login, read-only.
      readClearResult:({password,signal}={})=>run({password,signal},async api=>({
        log:validateCallHistory(await api.callLog()),
        settingsRevision:legacyPhoneSettingsRevision(await api.phoneCfg())})),
      readAutodial:({password,signal})=>run({password,signal},
        async api=>legacyAutodialSnapshot(await api.phoneCfg())),
      applyAutodial:({password,type,value,expectedRevision,beforeDispatch,signal})=>{
        if(typeof beforeDispatch!=='function'||typeof expectedRevision!=='string')fail('INVALID_ACTION');
        return run({password,signal},async api=>{
          const before=legacyAutodialSnapshot(await api.phoneCfg());
          if(before.revision!==expectedRevision)fail('AUTODIAL_STALE');
          const change=autoDialChanges(before,type,value);
          return api.nativeApply(change.rows.map(row=>[legacyAutodialField(row.name),row.newValue]),
            ()=>beforeDispatch({beforeRevision:before.revision,type,desired:change.desired}));
        });
      },
      ringTest:({password,beforeDispatch,signal})=>{
        if(typeof beforeDispatch!=='function')fail('INVALID_ACTION');
        // Native test_phone(): setCfg('ring_test',9); sendForm(...).
        return run({password,signal},api=>api.nativeApply([['ring_test','9']],beforeDispatch));
      }
    };
  }
  async initialize() {
    if (this.chromium) return;
    if (!this.initializing) this.initializing=(async()=>{
      const imported=await import(pathToFileURL(path.join(MODULE_DIR,'vendor/playwright-core/index.mjs')).href);
      this.chromium=imported.chromium;
    })();
    try {await this.initializing;} catch(error) {this.initializing=null;throw error;}
  }
  async read(password, options = {}) {
    return this.withSession(password,async session => {
      const snapshot=await session.snapshot();
      return {...snapshot,network:session.stats()};
    }, false, options);
  }
  async readCalls(password, options = {}) {
    return this.withSession(password, async session => session.callLog(), true, options);
  }
  async readDns(password, options = {}) {
    return this.withSession(password,async session=>session.dnsRead(),false,options);
  }
  /** Only read field NAMES from the authenticated DNS page.
   * Never return CGI source, CA values, passwords or session tokens.
   */
  async readDnsInventory(password,options={}){
    return this.withSession(password,async session=>{
      const current=await session.dnsRead();
      const data=await session.dnsInventory();
      const inventory=describeNativeDnsInventory(data);
      const observed0=inventory.observedValues.find(x=>x.name==='wan_dns0');
      if(observed0?.kind==='ipv4_pair'&&
        (observed0.primary!==current.primary||observed0.secondary!==current.secondary))
        fail('DNS_SCHEMA');
      return {...current,nativeDnsInventory:inventory};
    },false,options);
  }
  async prepareDns({password,primary,secondary,signal}) {
    const target=validateDnsPair({primary,secondary});
    return this.withSession(password,async session=>{
      const before=await session.dnsRead();
      if(before.primary===target.primary&&before.secondary===target.secondary)fail('DNS_UNCHANGED');
      const form=await session.dnsForm(target,before);
      validateDnsNativeForm(form,{fieldId:before.fieldId});
      return {before:{primary:before.primary,secondary:before.secondary,revision:before.revision},
        target,nativeFormVerified:true};
    },false,{signal});
  }
  async applyDns({password,primary,secondary,expectedRevision,beforeDispatch,signal}) {
    const target=validateDnsPair({primary,secondary});
    if(typeof beforeDispatch!=='function'||typeof expectedRevision!=='string'||
      !/^[a-f0-9]{64}$/.test(expectedRevision))fail('DNS_INVALID');
    return this.withSession(password,async session=>{
      const before=await session.dnsRead();
      if(before.revision!==expectedRevision)fail('STALE_PLAN');
      const form=await session.dnsForm(target,before);
      validateDnsNativeForm(form,{fieldId:before.fieldId});
      await beforeDispatch({beforeRevision:before.revision,before:{primary:before.primary,secondary:before.secondary}});
      const response=await session.submit(form,'dns');
      return {configurationPosts:session.stats().configurationPosts,response};
    },false,{signal});
  }
  /** WAN DNS mode (automatic/static) of the default-route profile. */
  async readDnsMode(password,options={}){
    return this.withSession(password,async session=>{
      const wan=await session.dnsRead();
      const mode=await session.dnsModeRead(wan);
      return {...mode,wan:{primary:wan.primary,secondary:wan.secondary}};
    },false,options);
  }
  async prepareDnsMode({password,target,signal}){
    const wanted=validateDnsModeTarget(target);
    return this.withSession(password,async session=>{
      const before=await session.dnsModeRead(await session.dnsRead());
      const changes=dnsModeChanges(before,wanted);
      if(!changes.length)fail('DNS_UNCHANGED');
      validateDnsModeForm(await session.dnsModeForm(changes,before),{changes});
      return {before:{route:before.route,automatic:before.automatic,primary:before.primary,
        secondary:before.secondary,revision:before.revision},
        target:wanted,changedFields:changes.map(c=>c.name),nativeFormVerified:true};
    },false,{signal});
  }
  async applyDnsMode({password,target,expectedRevision,beforeDispatch,signal}){
    const wanted=validateDnsModeTarget(target);
    if(typeof beforeDispatch!=='function'||typeof expectedRevision!=='string'||
      !/^[a-f0-9]{64}$/.test(expectedRevision))fail('DNS_INVALID');
    return this.withSession(password,async session=>{
      const before=await session.dnsModeRead(await session.dnsRead());
      if(before.revision!==expectedRevision)fail('STALE_PLAN');
      const changes=dnsModeChanges(before,wanted);
      if(!changes.length)fail('DNS_UNCHANGED');
      const form=await session.dnsModeForm(changes,before);
      validateDnsModeForm(form,{changes});
      await beforeDispatch({beforeRevision:before.revision,changedFields:changes.map(c=>c.name)});
      const response=await session.submit(form,'dns-mode');
      return {configurationPosts:session.stats().configurationPosts,response};
    },false,{signal});
  }
  /** Static, authenticated WAN-page inspection. No HTML/JS, cookies, tokens or
   * native CGI values escape the isolated browser. No WAN form is submitted.
   */
  async readWanNative(password,options={}){
    return this.withSession(password,async session=>session.wanPageInspection(),false,options);
  }
  async readDeviceInfo(password, options = {}) {
    return this.withSession(password,async session=>session.deviceInfo(),false,options);
  }
  async readAutodial({password,signal}){
    return this.withSession(password,session=>session.autodialSnapshot(),false,{signal});
  }
  async applyAutodial({password,type,value,expectedRevision,beforeDispatch,signal}){
    if(typeof beforeDispatch!=='function'||typeof expectedRevision!=='string')
      fail('INVALID_ACTION');
    return this.withSession(password,async session=>{
      const before=await session.autodialSnapshot();
      if(before.revision!==expectedRevision)fail('AUTODIAL_STALE');
      const changes=autoDialChanges(before,type,value);
      const form=await session.autodialForm(before,changes);
      assertNativeAutodialForm(form,before,changes);
      const still=await session.autodialSnapshot();
      if(still.revision!==expectedRevision)fail('AUTODIAL_STALE');
      await beforeDispatch({beforeRevision:before.revision,type,desired:changes.desired});
      const response=await session.submit(form,'autodial');
      return {configurationPosts:session.stats().configurationPosts,response};
    },false,{signal});
  }
  async ringTest({password,beforeDispatch,signal}) {
    if(typeof beforeDispatch!=='function')fail('INVALID_ACTION');
    return this.withSession(password,async session=>{
      const form=await session.ringTestForm();
      assertNativeRingTestForm(form);
      // This callback is the one-shot handoff. Do not retry under any failure.
      await beforeDispatch();
      const response=await session.submit(form,'ring-test');
      return {configurationPosts:session.stats().configurationPosts,response};
    },false,{signal});
  }
  async clearCalls({password,beforeDispatch}) {
    if (typeof beforeDispatch !== 'function') fail('INVALID_ACTION');
    return this.withSession(password, async session => {
      const log = validateCallHistory(await session.callLog());
      if (log.total === 0) fail('CALL_LOG_EMPTY');
      const before = await session.snapshot();
      if(before.compatibility && before.compatibility.features?.clearHistory!==true) fail('COMPAT_READ_ONLY');
      const form = await session.clearLogForm();
      assertNativeClearLogForm(form);
      const immediatelyBefore = await session.snapshot();
      if (immediatelyBefore.revision !== before.revision) fail('STALE_PLAN');
      if(immediatelyBefore.compatibility && immediatelyBefore.compatibility.features?.clearHistory!==true) fail('COMPAT_READ_ONLY');
      // Must persist a one-shot dispatch checkpoint before the irreversible POST.
      await beforeDispatch({beforeRevision:before.revision, observedCount:log.total});
      const response = await session.submit(form,'clear-history');
      return {configurationPosts:session.stats().configurationPosts, response,
        beforeRevision:before.revision};
    },true);
  }
  async prepare({password,type,pattern,ruleId}) {
    if(!['add','delete'].includes(type)) fail('INVALID_ACTION');
    return this.withSession(password,async session=>{
      const before=await session.snapshot();
      if(before.compatibility && before.compatibility.features?.[type]!==true) fail('COMPAT_READ_ONLY');
      if(type==='add') assertAddPreconditions(before.rows,pattern);
      else assertDeletePreconditions(before.rows,ruleId,pattern);
      const form=await session.form(before.rows,type,type==='add'?pattern:ruleId);
      assertNativeForm(form,before.rows,type);
      return {snapshot:before,type,form:{command:form.command,method:form.method,action:form.action,
        fieldNames:form.inputs.map(x=>x.name),configurationFields:0},network:session.stats()};
    });
  }
  async apply({password,type,pattern,ruleId,expectedRevision,beforeDispatch}) {
    if(!['add','delete'].includes(type)||typeof beforeDispatch!=='function'||!expectedRevision) fail('INVALID_ACTION');
    return this.withSession(password,async session => {
      const before=await session.snapshot();
      if(before.compatibility && before.compatibility.features?.[type]!==true) fail('COMPAT_READ_ONLY');
      if(before.revision!==expectedRevision) fail('STALE_PLAN');
      if(type==='add') assertAddPreconditions(before.rows,pattern);
      else assertDeletePreconditions(before.rows,ruleId,pattern);
      const form=await session.form(before.rows,type,type==='add'?pattern:ruleId);
      assertNativeForm(form,before.rows,type);
      const immediatelyBefore=await session.snapshot();
      if(immediatelyBefore.revision!==expectedRevision) fail('STALE_PLAN');
      if(immediatelyBefore.compatibility && immediatelyBefore.compatibility.features?.[type]!==true) fail('COMPAT_READ_ONLY');
      // The caller must durably reserve the checkpoint before this callback resolves.
      await beforeDispatch({beforeSnapshot:immediatelyBefore});
      const response=await session.submit(form,type);
      // Separate read() by the caller provides verification using another fresh login.
      return {configurationPosts:session.stats().configurationPosts,response,network:session.stats()};
    });
  }
  async withSession(password,work,captureCallLog=false,{signal,timeoutMs=REQUEST_BUDGETS.routerMs}={}) {
    if(typeof password!=='string'||!password||password.length>256) fail('CREDENTIAL_REQUIRED');
    if (!Number.isFinite(timeoutMs) || timeoutMs <= 0) fail('BAD_REQUEST');
    const currentOrigin=this.origin;
    let browser,context,permit=null,usedCount=0,loginCount=0;
    const controller = new AbortController();
    const deadline = performance.now() + timeoutMs;
    let closing = null;
    const closeBrowser = () => {
      permit = null;
      if (!closing && browser) closing = browser.close({reason: 'REAROUTER_SESSION_FINISHED'}).catch(() => {});
      return closing;
    };
    const abort = reason => {
      if (!controller.signal.aborted) controller.abort(reason);
      // Closing only this isolated browser interrupts navigation/evaluate/fetch.
      // The caller keeps its lock until this close and the task actually settle.
      void closeBrowser();
    };
    const externallyAborted = () => abort(signal.reason);
    if (signal?.aborted) externallyAborted(); else signal?.addEventListener('abort', externallyAborted, {once: true});
    const timer = setTimeout(() => abort(Object.assign(new Error('ROUTER_TIMEOUT'), {code:'ROUTER_TIMEOUT'})), timeoutMs); timer.unref?.();
    const remaining = (stageMs = REQUEST_BUDGETS.actionMs) => {
      controller.signal.throwIfAborted();
      const left = Math.ceil(deadline - performance.now());
      if (left <= 0) { abort(Object.assign(new Error('ROUTER_TIMEOUT'), {code:'ROUTER_TIMEOUT'})); controller.signal.throwIfAborted(); }
      return Math.max(1, Math.min(stageMs, left));
    };
    const network={requestCount:0,configurationPosts:0,authenticationPosts:0,blocked:[],failures:[],responses:[]};
    const firstCallLog=captureCallLog?createFirstCallLogCapture(currentOrigin):null;
    let callLogForwarded = false, callLogFailure = null;
    const safePath=u=>u.origin===currentOrigin&&(READ_PATHS.has(u.pathname)||['/login.cgi','/apply_abstract.cgi'].includes(u.pathname))?u.pathname:'<UNAPPROVED>';
    try {
      await this.initialize();
      remaining();
      browser=await this.chromium.launch({headless:true,executablePath:this.executablePath,
        args:['--disable-background-networking','--disable-component-update','--disable-sync','--no-first-run'],timeout:remaining(REQUEST_BUDGETS.launchMs)});
      remaining();
      context=await browser.newContext({acceptDownloads:false,serviceWorkers:'block'});
      context.on('request',()=>network.requestCount++);
      context.on('response',r=>{
        network.responses.push({method:r.request().method(),path:safePath(new URL(r.url())),status:r.status()});
        // Keep the initial phone-page CGI body in memory. Never issue a second GET.
        firstCallLog?.observe(r);
      });
      context.on('requestfailed',r=>network.failures.push({method:r.method(),path:safePath(new URL(r.url()))}));
      await context.route('**/*',async route=>{
        const r=route.request(),u=new URL(r.url());
        const request={origin:u.origin,path:u.pathname,search:u.search,method:r.method(),body:r.postData()||'',credentials:!!(u.username||u.password)};
        if(controller.signal.aborted || !allowRouterRequest(request,permit,usedCount,loginCount,currentOrigin)) {
          network.blocked.push({method:r.method(),path:safePath(u)});
          return route.abort();
        }
        if (u.pathname === '/cgi/cgi_call_log.js' && r.method() === 'GET') {
          // The native page's initial script request is the sole source. A
          // replacement fetch here forwards that paused request exactly once;
          // route.continue() is never called for it. The browser receives no
          // untrusted CGI JavaScript and subsequent native polling is local.
          if (firstCallLog && !callLogForwarded) {
            callLogForwarded = true;
            try {
              const result = await readBoundedCallLog({url:r.url(), origin:currentOrigin,
                headers:await r.allHeaders(), signal:controller.signal});
              firstCallLog.observe({url:()=>r.url(), request:()=>({method:()=> 'GET'}),
                status:()=>result.status, text:async()=>result.body});
            } catch (error) {
              callLogFailure = error;
            }
          }
          return route.fulfill({status:200, contentType:'application/javascript; charset=utf-8',
            body:'var voip_call_logs=[]; var call_logs=[];'});
        }
        if(r.method()==='POST') {
          if(u.pathname==='/login.cgi') {loginCount++;network.authenticationPosts=loginCount;}
          else {usedCount++;network.configurationPosts=usedCount;permit=null;}
        }
        return route.continue();
      });
      const page=await context.newPage();
      page.setDefaultTimeout(remaining(REQUEST_BUDGETS.actionMs));
      // Native page error contents can contain private values; never record their text.
      page.on('pageerror',()=>{});
      await page.goto(currentOrigin+'/index.htm',{waitUntil:'load',timeout:remaining(REQUEST_BUDGETS.navigationMs)});
      if(new URL(page.url()).pathname==='/login.htm') {
        const user=page.locator('[name="ui_user"]');
        if(await user.isEnabled()) await user.fill('admin');
        else if(await user.inputValue()!=='admin') fail('AUTH_USER');
        await page.locator('[name="ui_pws"]').fill(password);
        await page.locator('#bt_save').click({timeout: remaining()});
        try {await page.waitForURL(u=>!u.pathname.includes('login'),{timeout:remaining(REQUEST_BUDGETS.navigationMs),waitUntil:'load'});} catch { remaining(); }
      }
      if(new URL(page.url()).origin!==currentOrigin||/login/i.test(new URL(page.url()).pathname)) fail('AUTH_FAILED');
      await page.goto(currentOrigin+'/phones.htm',{waitUntil:'load',timeout:remaining(REQUEST_BUDGETS.navigationMs)});
      // Call-history reads do not depend on native write functions.
      if(!captureCallLog)
        await page.waitForFunction(()=>typeof URLToken==='function',null,{timeout:remaining()});
      const nativeCommands=await page.evaluate(()=>({
        add:typeof window.genForm==='function'&&window.subFormVoSippCallBlockAddIN==='ui_sipp_no_blk_add_incoming',
        delete:typeof window.genForm==='function'&&window.subFormVoSippCallBlockDelIN==='ui_sipp_no_blk_del_incoming',
        clear:typeof window.genForm==='function'&&window.subFormVoSippCallLogDelAll==='ui_call_log_del_all',
        ring:typeof window.genForm==='function'&&window.subFormVoRingTest==='ui_voip_ring_test_osp'
      }));
      async function cgi(resource) {
        const result=await page.evaluate(async ({resource,timeout})=>{
          const r=await fetch(URLToken(resource),{credentials:'same-origin',cache:'no-store',
            headers:{'X-Requested-With':'XMLHttpRequest'},signal:AbortSignal.timeout(timeout)});
          // The fixed block/telephone schemas do not need an unbounded body.
          // Bound bytes while streaming, before constructing a string.
          const maximum = 256 * 1024;
          if (Number(r.headers.get('content-length')) > maximum) { await r.body?.cancel(); return {status:r.status,tooLarge:true}; }
          const reader = r.body.getReader(), chunks = []; let size = 0;
          for (;;) { const {done,value} = await reader.read(); if (done) break; size += value.byteLength; if (size > maximum) { await reader.cancel(); return {status:r.status,tooLarge:true}; } chunks.push(value); }
          const bytes = new Uint8Array(size); let at = 0;
          for (const chunk of chunks) { bytes.set(chunk,at); at += chunk.byteLength; }
          return {status:r.status,body:new TextDecoder().decode(bytes)};
        },{resource,timeout:remaining(REQUEST_BUDGETS.cgiMs)});
        remaining();
        if (result.status === 401 || result.status === 403) fail('AUTH_FAILED');
        if (result.tooLarge) fail('READ_UNAVAILABLE');
        if(result.status!==200) fail('READ_UNAVAILABLE');
        return result.body;
      }
      let dnsFrame=null;
      const session={
        stats:()=>({...network,configurationPosts:usedCount}),
        autodialSnapshot:async()=>{
          const data=inspectPhoneCgi(await cgi('/cgi/cgi_phones.js'));
          if(data.exact!==true)fail('AUTODIAL_SCHEMA');
          return parseAutodialFields(data.fields);
        },
        autodialForm:async(before,change)=>{
          // All six fields are observed from the native CGI. Only the matching
          // pair is cloned and changed; every other setting stays absent.
          await page.waitForFunction(()=>typeof getCfgObj==='function'&&
            typeof genForm==='function'&&
            getCfgObj('phone_hotline_enable_0')!==null,null,{
              timeout:remaining(REQUEST_BUDGETS.cgiMs)});
          return page.evaluate(({before,change})=>{
            if(subFormVoSippHotLineOSP!=='ui_sipp_hotline_osp')throw Error('AUTODIAL_FORM_MISMATCH');
            for(const r of before.rows){
              const native=getCfgObj(r.name);
              if(!native||Number(native.i)!==r.id||getCfg(r.name)!==r.value)
                throw Error('AUTODIAL_FORM_MISMATCH');
            }
            const savedCA=CA,savedExtra=frmExtraElm,
              savedOutput=typeof OUTF==='string'?OUTF:null;
            try{
              CA=change.rows.map(r=>({i:r.id,n:r.name,v:r.value,o:r.value,e:0}));
              frmExtraElm='';
              for(const r of change.rows)
                if(String(setCfg(r.name,r.newValue))!==r.newValue)
                  throw Error('AUTODIAL_FORM_MISMATCH');
              const html=genForm('RUX_AUTO_DIAL',{cmd:subFormVoSippHotLineOSP,
                cmdparam:'',next:'phones.htm',to:'apply_abstract.cgi'});
              const form=new DOMParser().parseFromString(html,'text/html').forms[0];
              if(!form)throw Error('AUTODIAL_FORM_MISMATCH');
              const inputs=[...form.querySelectorAll('input')].map(x=>({name:x.name,value:x.value}));
              const named=n=>inputs.find(x=>x.name===n)?.value;
              const changed=CA.filter(r=>r.v!==r.o).map(r=>r.n);
              return {command:subFormVoSippHotLineOSP,method:form.method,
                action:form.getAttribute('action'),inputs,integrity:{
                  actionEncoded:named('action')===do_encode('ui_sipp_hotline_osp'),
                  valuesEncoded:change.rows.every(r=>named(String(r.id))===do_encode(r.newValue)),
                  onlyExpectedChanged:changed.length===2&&
                    change.rows.every(r=>changed.includes(r.name))
                }};
            }finally{
              CA=savedCA;frmExtraElm=savedExtra;
              if(savedOutput!==null)OUTF=savedOutput;
            }
          },{before,change});
        },

        dnsRead:async()=>{
          remaining();
          try{
            // The real Livebox index.htm is a frameset with a mainFrame.
            // Keep its topFrame alive: native DNS code depends on top-level
            // form/token/progress state. The isolated test router also allows
            // a direct-page fallback when it has no frameset.
            await page.goto(currentOrigin+'/index.htm',{
              waitUntil:'load',timeout:remaining(REQUEST_BUDGETS.navigationMs)
            });
            const child=page.frame({name:'mainFrame'});
            if(child){
              await child.goto(currentOrigin+'/advanced_network_dns.htm',{
                waitUntil:'load',timeout:remaining(REQUEST_BUDGETS.navigationMs)
              });
              dnsFrame=child;
            }else{
              await page.goto(currentOrigin+'/advanced_network_dns.htm',{
                waitUntil:'load',timeout:remaining(REQUEST_BUDGETS.navigationMs)
              });
              dnsFrame=page.mainFrame();
            }
          }catch(error){
            if(controller.signal.aborted)throw error;
            fail('DNS_PAGE_UNAVAILABLE');
          }
          if(!dnsFrame||new URL(dnsFrame.url()).origin!==currentOrigin||
            new URL(dnsFrame.url()).pathname!=='/advanced_network_dns.htm')
            fail('DNS_PAGE_UNAVAILABLE');
          try{
            await dnsFrame.waitForFunction(()=>typeof getCfg==='function'&&
              typeof getCfgObj==='function'&&typeof genForm==='function'&&
              typeof subFormDNSConf==='string',null,{
                timeout:remaining(REQUEST_BUDGETS.cgiMs)
              });
          }catch(error){
            if(controller.signal.aborted)throw error;
            fail('DNS_FUNCTIONS_MISSING');
          }
          // The native page loads CGI values asynchronously after its
          // global helpers. Do not classify a still-loading field as absent.
          try{
            await dnsFrame.waitForFunction(()=>{
              const field=typeof getCfgObj==='function'?
                getCfgObj('wan_dns0'):null;
              return !!field;
            },null,{timeout:remaining(REQUEST_BUDGETS.cgiMs)});
          }catch(error){
            if(controller.signal.aborted)throw error;
            fail('DNS_FIELD_MISSING');
          }
          const observed=await dnsFrame.evaluate(()=>{
            // The firmware's getCfgObj calls Arcdecode and can mutate
            // CA[i].o independently of CA[i].v. Comparing the two or
            // every unrelated CA row falsely rejects untouched DNS.
            const item=getCfgObj('wan_dns0');
            return {fieldId:item?Number(item.i):null,
              raw:item?getCfg('wan_dns0'):null,
              validCmd:subFormDNSConf==='DNS_CONF'};
          });
          if(!observed.validCmd)fail('DNS_COMMAND_MISSING');
          if(!Number.isSafeInteger(observed.fieldId)||observed.fieldId<=0)
            fail('DNS_FIELD_MISSING');
          const current=parseDnsValue(observed.raw);
          return {...current,raw:observed.raw,fieldId:observed.fieldId,
            revision:dnsRevision({raw:observed.raw,fieldId:observed.fieldId})};
        },
        dnsInventory:async()=> {
          if(!dnsFrame || new URL(dnsFrame.url()).origin!==currentOrigin||
             new URL(dnsFrame.url()).pathname!=='/advanced_network_dns.htm')
            fail('DNS_PAGE_UNAVAILABLE');
          return dnsFrame.evaluate(()=>{
            // The CA array can contain unrelated and sensitive settings.
            // Inspect DNS-related NAMES only, with an explicit secret-name
            // exclusion. No raw CGI, passwords or unknown values leave the
            // isolated browser. This cannot mutate the router.
            if(!Array.isArray(CA)||CA.length>50000)
              throw Error('DNS_SCHEMA');
            const valid=/^[a-z][a-z0-9_]{1,64}$/i;
            const relates=/dns|resolver|resolv|forward|proxy|dnsmasq|relay/i;
            const secret=/passw|passwd|pwd|secret|token|cookie|credential|auth|privatekey|accesskey|ssid|sipp?ass|serial|pin\d|wpa|wifi/i;
            const unique=new Set();
            for(const row of CA){
              const n=row?.n;
              if(typeof n==='string'&&valid.test(n)&&relates.test(n)&&
                 !secret.test(n))unique.add(n);
            }
            const names=[...unique];
            // Keep wan_dns0, DNS forwarding/proxy candidates and GPON-like
            // identifiers ahead of old DSL profiles or host entries.
            const priority=n=>/^wan_dns\d+$/i.test(n)?0:
              /^(?:dns_proxy|dns_relay|dns_forward|resolv|resolver|dnsmasq|forward_dns)/i.test(n)?1:
              /^ipv6_wan_dns/i.test(n)?2:/^dslx_dns/i.test(n)?3:
              /^dns_(?:hostname|ip)\d+$/i.test(n)?4:5;
            names.sort((a,b)=>priority(a)-priority(b)||a.localeCompare(b,'en'));
            const included=names.slice(0,2048);
            const observedValues=[];
            const readSafe=(n)=>{
              // Read four exact WAN DNS fields and selected DSL-profile
              // flags/IPs ONLY. Do not return arbitrary CA values.
              const isWan=/^wan_dns[0-3]$/i.test(n);
              const isDsl=/^dslx_dns(?:(?:1|2)_[0-3]|enable[0-3])$/i.test(n);
              if((!isWan&&!isDsl)||typeof getCfg!=='function')return;
              let raw;
              try{raw=getCfg(n);}catch{return}
              if(typeof raw!=='string'||raw.length>63){
                if(isWan)observedValues.push({name:n,kind:'unrecognized'});
                return;
              }
              const v=raw.trim();
              const validIp=ip=>/^(?:\d{1,3}\.){3}\d{1,3}$/.test(ip)&&
                ip.split('.').every(x=>Number(x)<=255&&
                  (x.length===1||x[0]!=='0'));
              if(isWan){
                const items=v.split(/\s+/);
                if(items.length===2&&items.every(validIp))
                  observedValues.push({name:n,kind:'ipv4_pair',
                    primary:items[0],secondary:items[1]});
                else observedValues.push({name:n,kind:'unrecognized'});
              }else if(/^dslx_dns(?:1|2)_[0-3]$/i.test(n)){
                if(!validIp(v))return;
                observedValues.push({name:n,kind:'ipv4',value:v});
              }else if(/^dslx_dnsenable[0-3]$/i.test(n)&&
                (v==='0'||v==='1')){
                observedValues.push({name:n,kind:'flag',value:v==='1'});
              }
            };
            for(const n of included)readSafe(n);
            return {totalConfigFields:CA.length,matchingFields:names.length,
              truncated:names.length>included.length,
              names:included,observedValues};
          });
        },
        wanPageInspection:async()=>{
          remaining();
          const pages=await page.evaluate(async timeout=>{
            const paths=['/advanced_network_configuration.htm','/advanced_network_upnp.htm'];
            const commandNames=['WAN_CONN','WAN_DISC','WANETH_CONN','WANETH_DISC',
              'wan_start','wan_stop','subFormWANConn','subFormWANDisc',
              'subFormWANETHConn','subFormWanEthDisc'];
            const safeName=x=>typeof x==='string'&&/^[a-z][a-z0-9_-]{0,55}$/i.test(x)&&
              !/pass|token|cookie|secret|key|auth|csrf|session|serial|ssid|pin|user/i.test(x);
            const commandPresent=(text,name)=>
              (text.match(new RegExp('(?:^|[^A-Za-z0-9_])'+name+'(?:$|[^A-Za-z0-9_])','g'))||[]).length;
            const report=[];
            for(const wanted of paths){
              const base={path:wanted,status:'UNAVAILABLE',htmlBytes:0,
                forms:[],controls:[],commands:[],functions:[],linkedScripts:[]};
              try{
                const url=new URL(wanted,location.origin);
                if(url.origin!==location.origin||url.search||url.hash)throw Error('INVALID_NATIVE_URL');
                const resp=await fetch(url.pathname,{method:'GET',credentials:'same-origin',
                  cache:'no-store',redirect:'follow',signal:AbortSignal.timeout(timeout)});
                const final=new URL(resp.url);
                if(final.origin!==location.origin||final.pathname!==wanted||
                  resp.redirected){base.status='REDIRECT_OR_LOGIN';report.push(base);continue;}
                if(resp.status!==200){base.status='HTTP_'+resp.status;report.push(base);continue;}
                if(!/^text\/html(?:;|$)/i.test(resp.headers.get('content-type')||'')){
                  base.status='UNEXPECTED_CONTENT_TYPE';report.push(base);continue;
                }
                if(Number(resp.headers.get('content-length'))>131072){
                  await resp.body?.cancel();base.status='BODY_TOO_LARGE';report.push(base);continue;
                }
                if(!resp.body){base.status='EMPTY_RESPONSE';report.push(base);continue;}
                const reader=resp.body.getReader();let total=0;const chunks=[];
                for(;;){
                  const {done,value}=await reader.read();if(done)break;
                  total+=value.byteLength;
                  if(total>131072){await reader.cancel();throw Error('BODY_TOO_LARGE');}
                  chunks.push(value);
                }
                const bytes=new Uint8Array(total);let pos=0;
                for(const block of chunks){bytes.set(block,pos);pos+=block.byteLength;}
                base.htmlBytes=total;
                const html=new TextDecoder('utf-8',{fatal:true}).decode(bytes);
                const parsed=new DOMParser().parseFromString(html,'text/html');
                // Parsing with DOMParser is inert: script elements are never executed.
                const forms=[...parsed.querySelectorAll('form')].slice(0,25);
                base.forms=forms.map(form=>{
                  const action=form.getAttribute('action')||'';
                  let actionPath='';
                  try{
                    const a=new URL(action,location.origin+wanted);
                    if(a.origin===location.origin&&!a.search&&!a.hash&&
                      /^\/[a-z0-9_./-]{1,80}$/i.test(a.pathname))actionPath=a.pathname;
                  }catch{}
                  return {method:(form.getAttribute('method')||'GET').toUpperCase(),
                    actionPath,fieldCount:form.querySelectorAll('input,select,textarea').length,
                    hasHiddenFields:form.querySelector('input[type="hidden"]')!==null};
                });
                const controls=[...parsed.querySelectorAll('button,input[type="button"],input[type="submit"],a[onclick]')].slice(0,70);
                base.controls=controls.map(el=>{
                  const attr=el.getAttribute('onclick')||'';
                  const matches=commandNames.filter(command=>commandPresent(attr,command)>0);
                  return {tag:el.tagName.toLowerCase(),
                    id:safeName(el.id)?el.id:null,relatedCommands:matches,
                    hasClickHandler:!!attr};
                });
                const scripts=[...parsed.querySelectorAll('script')];
                const inline=scripts.filter(el=>!el.src).map(el=>el.textContent||'').join('\n');
                const handlers=[...parsed.querySelectorAll('[onclick],[onchange]')].map(el=>
                  (el.getAttribute('onclick')||'')+'\n'+(el.getAttribute('onchange')||'')).join('\n');
                base.commands=commandNames.map(name=>({
                  name,scriptReferences:Math.min(100,commandPresent(inline,name)),
                  handlerReferences:Math.min(100,commandPresent(handlers,name)),
                  hasFormDispatchReference: new RegExp(
                    '(?:subForm|genForm)\\s*\\([\\s\\S]{0,400}'+name).test(inline)
                })).filter(item=>item.scriptReferences||item.handlerReferences||item.hasFormDispatchReference);
                base.functions=[...new Set(
                  [...inline.matchAll(/\bfunction\s+([a-z_][a-z0-9_]{1,60})\s*\(/gi)]
                    .map(v=>v[1]).filter(n=>safeName(n)&&/wan|connect|internet|network|gpon|dsl|init/i.test(n))
                )].slice(0,24);
                base.linkedScripts=scripts.filter(x=>x.src).map(x=>{
                  try{
                    const u=new URL(x.getAttribute('src'),location.origin+wanted);
                    if(u.origin!==location.origin)return null;
                    const m=u.pathname.match(/^\/(?:cgi|js)\/([a-z0-9_-]{1,70}\.js)$/i);
                    return m?u.pathname:null;
                  }catch{return null}
                }).filter(Boolean).slice(0,30);
                base.status='HTML_INSPECTED';
              }catch(error){
                // Exception messages and raw HTML may contain credentials.
                base.status=error?.name==='TimeoutError'?'READ_TIMEOUT':'READ_UNAVAILABLE';
              }
              report.push(base);
            }
            return report;
          },remaining(REQUEST_BUDGETS.cgiMs));
          remaining();
          // Additional server-side strict schema checks below run before publication.
          if(!Array.isArray(pages)||pages.length!==2||
            pages[0].path!=='/advanced_network_configuration.htm'||
            pages[1].path!=='/advanced_network_upnp.htm')fail('READ_UNAVAILABLE');
          return {schema:1,pages,configurationPosts:network.configurationPosts};
        },
        dnsModeRead:async wan=>{
          if(!dnsFrame||new URL(dnsFrame.url()).pathname!=='/advanced_network_dns.htm')
            fail('DNS_PAGE_UNAVAILABLE');
          // Three named rows only; no other CA value leaves the browser.
          const observed=await dnsFrame.evaluate(()=>{
            const route=getCfg('wan_defRoute');
            const row=n=>{const x=getCfgObj(n);return x?{name:n,id:Number(x.i),
              encrypted:!(x.e==null||x.e==0),value:getCfg(n)}:null;};
            return {route,encoder:typeof do_encode==='function',
              command:typeof subFormDNSHost==='string'?subFormDNSHost:null,
              rows:/^[0-3]$/.test(route)?['dslx_dnsenable'+route,'dslx_dns1_'+route,
                'dslx_dns2_'+route].map(row):null};
          });
          return parseDnsMode(observed,wan);
        },
        dnsModeForm:async(changes,before)=>dnsFrame.evaluate(({changes,before})=>{
          if(subFormDNSHost!=='ui_dns'||typeof do_encode!=='function'||
            getCfg('wan_defRoute')!==before.route)throw Error('DNS_FORM_MISMATCH');
          // Clone exactly the three mode rows, re-checked against the plan.
          const rows=before.rows.map(r=>{
            const x=getCfgObj(r.name);
            if(!x||Number(x.i)!==r.id||!(x.e==null||x.e==0)||getCfg(r.name)!==r.value)
              throw Error('DNS_FORM_MISMATCH');
            return {i:r.id,n:r.name,v:r.value,o:r.value,e:0};
          });
          const previousCA=CA,previousExtra=frmExtraElm;
          const previousOutput=typeof OUTF==='string'?OUTF:null;
          try{
            CA=rows;frmExtraElm='';
            for(const c of changes)if(setCfg(c.name,c.value)!==c.value)throw Error('DNS_FORM_MISMATCH');
            const changed=CA.filter(x=>Number(x.i)>0&&x.v!==x.o).map(x=>x.n);
            const html=genForm('RUX_DNS_MODE',{cmd:subFormDNSHost,
              cmdparam:'',next:'advanced_network_dns.htm',to:'apply_abstract.cgi'});
            const dom=new DOMParser().parseFromString(html,'text/html').forms[0];
            if(!dom)throw Error('DNS_FORM_MISMATCH');
            const inputs=[...dom.querySelectorAll('input')].map(x=>({name:x.name,value:x.value}));
            const named=name=>inputs.find(x=>x.name===name)?.value;
            return {command:subFormDNSHost,method:dom.method,action:dom.getAttribute('action'),
              inputs,integrity:{actionEncoded:named('action')===do_encode('ui_dns'),
                valuesEncoded:changes.every(c=>named(String(c.id))===do_encode(c.value)),changed}};
          }finally{
            CA=previousCA;frmExtraElm=previousExtra;
            if(previousOutput!==null)OUTF=previousOutput;
          }
        },{changes,before}),
        dnsForm:async(target,before)=>dnsFrame.evaluate(({target,before})=>{
          const value=target.primary+' '+target.secondary;
          const field=getCfgObj('wan_dns0');
          if(!field||Number(field.i)!==before.fieldId||
            getCfg('wan_dns0')!==before.raw||subFormDNSConf!=='DNS_CONF'||
            typeof do_encode!=='function')throw Error('DNS_FORM_MISMATCH');
          // Construct the native form from exactly ONE cloned configuration
          // field. Do not copy the entire CA array: it may contain unrelated
          // fields or encrypted original-value representations.
          const previousCA=CA;
          const previousExtra=frmExtraElm;
          const previousOutput=typeof OUTF==='string'?OUTF:null;
          try{
            CA=[{i:Number(field.i),n:'wan_dns0',
              v:before.raw,o:before.raw,e:0}];
            frmExtraElm='';
            if(setCfg('wan_dns0',value)!==value)throw Error('DNS_FORM_MISMATCH');
            const changes=CA.filter(x=>Number(x.i)>0&&x.v!==x.o).map(x=>x.n);
            const onlyDnsChanged=changes.length===1&&changes[0]==='wan_dns0';
            const html=genForm('RUX_DNS',{cmd:subFormDNSConf,
              cmdparam:'',next:'advanced_network_dns.htm',to:'apply_abstract.cgi'});
            const dom=new DOMParser().parseFromString(html,'text/html').forms[0];
            if(!dom)throw Error('DNS_FORM_MISMATCH');
            const inputs=[...dom.querySelectorAll('input')].map(x=>({name:x.name,value:x.value}));
            const named=name=>inputs.find(x=>x.name===name)?.value;
            return {command:subFormDNSConf,method:dom.method,
              action:dom.getAttribute('action'),inputs,
              integrity:{actionEncoded:named('action')===do_encode('DNS_CONF'),
                dnsValueEncoded:named(String(field.i))===do_encode(value),
                onlyDnsChanged},fieldId:Number(field.i)};
          }finally{
            CA=previousCA;
            frmExtraElm=previousExtra;
            if(previousOutput!==null)OUTF=previousOutput;
          }
        },{target,before}),
        deviceInfo:async()=>{
          remaining();
          const routerStatus=await cgi('/cgi/cgi_router_status.js');
          const info=await cgi('/cgi/cgi_info.js');
          return parseRouterDeviceInfo({routerStatus,info});
        },
        snapshot:async()=>{
          remaining();
          const block=inspectBlockCgi(await cgi('/cgi/cgi_tel_call_blocking.js'));
          const phoneBody=await cgi('/cgi/cgi_phones.js');
          // Invalid/extended telephone CGI never permits a write, but a
          // structurally verified block list can still be displayed.
          let telephone;
          try{telephone=inspectPhoneCgi(phoneBody);}
          catch(error){
            if(error?.code!=='COMPAT_SCHEMA')throw error;
            telephone={exact:false,count:0,fields:[],digest:sha(phoneBody),fingerprint:null};
          }
          const compatibility=composeCompatibility({block,phone:telephone,commands:nativeCommands});
          const snapshot={rows:block.rows,
            phone:{fields:telephone.count,sha256:telephone.digest},
            lineNumber:extractConfiguredFixedLine(telephone.fields),
            compatibility,capturedAt:new Date().toISOString()};
          // The historic makeRevision() remains strict for write-safe snapshots.
          snapshot.revision=compatibility.safeWrites?makeRevision(snapshot):
            sha(JSON.stringify([stateHash(snapshot.rows),snapshot.phone.sha256]));
          return snapshot;
        },
        callLog:async()=>{
          if(!firstCallLog) fail('READ_UNAVAILABLE');
          if (callLogFailure) throw callLogFailure;
          return await firstCallLog.read(Math.min(30_000,remaining(REQUEST_BUDGETS.cgiMs)));
        },
        form:async(rows,type,parameter)=>page.evaluate(({rows,type,parameter})=>{
          const command=type==='add'?subFormVoSippCallBlockAddIN:subFormVoSippCallBlockDelIN;
          const previous=CA;
          try {
            CA=[];for(const r of rows) addCfg(r.name,r.id,r.value);
            const html=genForm('RUX_REAROUTER_MANAGER',{cmd:command,cmdparam:parameter,next:'phones.htm',to:'apply_abstract.cgi'});
            const form=new DOMParser().parseFromString(html,'text/html').forms[0];
            if(!form) throw Error('FORM_MISSING');
            const inputs=[...form.querySelectorAll('input')].map(x=>({name:x.name,value:x.value}));
            const value=name=>inputs.find(x=>x.name===name)?.value;
            const encoded=typeof do_encode==='function';
            return {command,method:form.method,action:form.getAttribute('action'),
              inputs,integrity:{
                actionEncoded:encoded&&value('action')===do_encode(command),
                parameterEncoded:encoded&&value('action_params')===do_encode(String(parameter)),
              }};
          } finally {CA=previous;}
        },{rows,type,parameter}),
        ringTestForm:async()=>page.evaluate(()=>{
          if(typeof window.subFormVoRingTest!=='string'||
             window.subFormVoRingTest!=='ui_voip_ring_test_osp'||
             typeof window.genForm!=='function')throw Error('NATIVE_RING_UNAVAILABLE');
          const previous=CA;
          try{
            CA=[];
            const markup=genForm('RUX_REAROUTER_MANAGER',{
              cmd:window.subFormVoRingTest,cmdparam:'',next:'phones.htm',to:'apply_abstract.cgi'});
            const form=new DOMParser().parseFromString(markup,'text/html').forms[0];
            if(!form)throw Error('FORM_MISSING');
            const inputs=[...form.querySelectorAll('input')].map(x=>({name:x.name,value:x.value}));
            return {command:window.subFormVoRingTest,method:form.method,action:form.getAttribute('action'),
              inputs,integrity:{actionEncoded:typeof window.do_encode==='function'&&
                inputs.find(x=>x.name==='action')?.value===window.do_encode(window.subFormVoRingTest)}};
          }finally{CA=previous;}
        }),
        clearLogForm: async () => page.evaluate(() => {
          if (typeof subFormVoSippCallLogDelAll !== 'string' ||
              subFormVoSippCallLogDelAll !== 'ui_call_log_del_all') throw Error('NATIVE_CLEAR_UNAVAILABLE');
          const previous = CA;
          try {
            CA=[];
            const html=genForm('RUX_REAROUTER_MANAGER',{
              cmd:subFormVoSippCallLogDelAll,cmdparam:'',next:'phones.htm',to:'apply_abstract.cgi'});
            const form=new DOMParser().parseFromString(html,'text/html').forms[0];
            if (!form) throw Error('FORM_MISSING');
            const inputs=[...form.querySelectorAll('input')].map(x=>({name:x.name,value:x.value}));
            const encoded=typeof do_encode==='function';
            return {command:subFormVoSippCallLogDelAll,
              method:form.method,action:form.getAttribute('action'),
              inputs,integrity:{
                actionEncoded:encoded&&
                  inputs.find(x=>x.name==='action')?.value===do_encode(subFormVoSippCallLogDelAll),
              }};
          } finally { CA=previous; }
        }),
        submit:async(form,type)=>{
          remaining();
          if(usedCount!==0||permit) fail('ATTEMPT_CONSUMED');
          const body=new URLSearchParams(form.inputs.map(x=>[x.name,x.value])).toString();
          permit={type,body};
          try {
            if(type==='dns'||type==='dns-mode'){
              // Do NOT dispatch DNS_CONF from the top-level index document.
              // The live firmware's native subForm() posts from the DNS frame
              // into an OUTfrm iframe, with Sec-Fetch-Mode:navigate and
              // Referer:advanced_network_dns.htm. A top-level fetch differs.
              if(!dnsFrame || new URL(dnsFrame.url()).origin!==currentOrigin ||
                new URL(dnsFrame.url()).pathname!=='/advanced_network_dns.htm' ||
                !page.frame({name:'OUTfrm'})) fail('DNS_FORM_MISMATCH');
              // Install observation BEFORE the only form.submit(). Do not
              // execute, store or inspect the returned CGI HTML/JavaScript.
              const response= context.waitForEvent('response',{
                predicate:r=>r.request().method()==='POST' &&
                  new URL(r.url()).origin===currentOrigin &&
                  new URL(r.url()).pathname==='/apply_abstract.cgi',
                timeout:remaining(REQUEST_BUDGETS.submitMs)
              }).then(r=>({status:r.status(),transportError:false,nativeForm:true}))
                .catch(()=>({status:null,transportError:true,nativeForm:true}));
              try{
                await dnsFrame.evaluate(({fields})=>{
                  // The validated fields are fixed and are the only inputs.
                  // Native HTTP navigation retains the DNS frame as Referer
                  // and the same hidden OUTfrm destination as Livebox.
                  const f=document.createElement('form');
                  f.method='POST';f.action='apply_abstract.cgi';
                  f.target='OUTfrm';f.style.display='none';
                  for(const item of fields){
                    const input=document.createElement('input');
                    input.type='hidden';input.name=item.name;input.value=item.value;
                    f.append(input);
                  }
                  document.body.append(f);
                  HTMLFormElement.prototype.submit.call(f);
                },{fields:form.inputs});
              }catch{
                // The submission may already have been dispatched. The caller
                // classifies the outcome as uncertain and NEVER retries.
                return {status:null,transportError:true,nativeForm:true};
              }
              return await response;
            }
            return await page.evaluate(async ({body,timeout})=>{
              try {
                const r=await fetch('/apply_abstract.cgi',{method:'POST',credentials:'same-origin',redirect:'error',
                  headers:{'Content-Type':'application/x-www-form-urlencoded'},body,signal:AbortSignal.timeout(timeout)});
                // Status is enough; never materialize an arbitrary action body.
                await r.body?.cancel();return {status:r.status,transportError:false};
              } catch {return {status:null,transportError:true};}
            },{body,timeout:remaining(REQUEST_BUDGETS.submitMs)});
          } finally {permit=null;}
        },
      };
      const value = await work(session); remaining(); return value;
    } catch(error) {
      // Do not expose native Playwright errors, request bodies, tokens, or credentials.
      const allowed=new Set(['CREDENTIAL_REQUIRED','INVALID_ACTION','BASELINE_INTEGRITY','STALE_PLAN','AUTH_USER','AUTH_FAILED',
        'ROUTER_TIMEOUT','REQUEST_CANCELLED','NOT_AUTHENTICATED','STOPPING','READ_UNAVAILABLE','CALL_LOG_SCHEMA','CALL_LOG_TOO_LARGE','ROUTER_SCHEMA_CHANGED','PHONE_SCHEMA','FORM_MISMATCH','FORM_CONFIGURATION_FIELDS',
        'ATTEMPT_CONSUMED','PATTERN_ALREADY_PRESENT','INCOMING_CAPACITY','PROFILES_ENABLED','DELETE_ID_NOT_FOUND',
        'DELETE_PATTERN_MISMATCH','INVALID_EXACT_PATTERN','PREFIX_OVERLAP','PREFIX_EXISTING_PATTERN_UNVERIFIED','INVALID_EXISTING_PATTERN','INVALID_RULE_ID','INVALID_FIELD_COUNT','INVALID_CGI',
        'COUNTER_MISMATCH','DUPLICATE_RULE_ID','CALL_LOG_EMPTY',
        'NATIVE_RING_UNAVAILABLE',
        'AUTODIAL_SCHEMA','AUTODIAL_STALE','AUTODIAL_FORM_MISMATCH','AUTODIAL_UNCHANGED','AUTODIAL_INVALID',
        'COMPAT_SCHEMA','COMPAT_REQUIRED_FIELD_MISSING','COMPAT_READ_ONLY',
        'DEVICE_INFO_SCHEMA','DNS_INVALID','DNS_UNAVAILABLE','DNS_SCHEMA',
        'DNS_FORM_MISMATCH','DNS_UNCHANGED','DNS_PAGE_UNAVAILABLE',
        'DNS_FUNCTIONS_MISSING','DNS_COMMAND_MISSING','DNS_FIELD_MISSING']);
      const reason = controller.signal.aborted ? controller.signal.reason : error;
      fail(allowed.has(reason?.code)?reason.code:'ROUTER_UNAVAILABLE');
    } finally {
      permit=null;
      clearTimeout(timer); signal?.removeEventListener('abort', externallyAborted);
      // close() disposes all isolated contexts and in-flight requests. Do not
      // return (and release routerWork) while that cleanup is still pending.
      if(browser) await closeBrowser();
      password = null;
    }
  }
}

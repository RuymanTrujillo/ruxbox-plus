import {APP_INFO} from './app-info.mjs';
import {setupCallHistoryView} from './call-history-view.mjs';
import {REQUEST_BUDGETS, requestBudget} from './request-budget.mjs';
import {selectExactBatch, runExactBatch} from './policy-batch.mjs';

import {setupCallMonitor} from './call-monitor.mjs';
import {setupDnsUI} from './dns-ui.mjs';
import {setupRouterInfoDialog} from './router-info-dialog.mjs';
import {legacyCapturedAt,legacyReadVerified,legacyReadStatus,legacyReadMessage,legacyDnsLabel,legacyRefreshFailed,withLegacyHistory} from './legacy-readback.mjs';
const $ = (id) => document.getElementById(id);

// El pie se rellena una sola vez y no necesita sesión, lecturas del router
// ni acceso a servicios externos. textContent evita interpretar el contenido.
function renderAppFooter(){
  const slots={
    footerAppName:APP_INFO.name,
    footerAppVersion:'Versión '+APP_INFO.version,
    footerAuthor:APP_INFO.author,
    footerAppDescription:APP_INFO.description,
    footerAppNotice:APP_INFO.notice
  };
  for(const [id,value] of Object.entries(slots)){
    const element=$(id);
    if(!element)throw Error('MISSING_FOOTER_ELEMENT_'+id);
    element.textContent=value;
  }
  $('footerAuthor').href=APP_INFO.authorUrl;
  $('footerRepository').href=APP_INFO.repositoryUrl;
  $('brandTagline').textContent=APP_INFO.description;
}
renderAppFooter();
const ui = Object.fromEntries([
  'bootView', 'connectionView', 'connectionTargetIp', 'dashboard', 'connectForm', 'password', 'connectButton', 'connectError',
  'disconnectButton', 'refreshButton', 'connectionStatus', 'connectionText', 'capturedTime', 'lineIdentity', 'lineNumber',
  'compatBadge','compatibilityHelp','compatibilityDescription','compatibilityFeatures',
  'routerInfoDialog','routerInfoTitle','routerInfoLocal','routerInfoLocalStatus','routerInfoLocalReload','routerInfoNetwork','routerInfoNetworkStatus',
  'routerInfoFunctions','routerInfoClose','routerInfoReload','policyExampleButton',
  'notice', 'noticeText', 'noticeIcon', 'rulesPanel', 'rulesLoading', 'rulesUnavailable', 'rulesEmpty', 'rulesList', 'ruleCount',
  'additionalConfig', 'addForm', 'addMode', 'numberLabel', 'numberNote', 'prefixPreview', 'numberInput', 'numberError', 'addButton', 'writeNote',
  'reviewBanner', 'reviewTitle', 'reviewText', 'reviewRefreshButton', 'warningsPanel', 'warningsList',
  'activityList', 'activityEmpty', 'activityCount', 'confirmDialog', 'confirmTitle',
  'confirmNumber', 'confirmSummary', 'confirmExpiry', 'confirmError', 'commitButton',
  'cancelPlanButton', 'announcer',
  'policyDesigner', 'policyForm', 'policyBlocks', 'policyAddBlockButton', 'policyExceptions',
  'policySamples', 'policyPreviewButton', 'policyError', 'policyResults', 'policyResultTitle',
  'policyCalculatedAt', 'policyCoverage', 'policyMaskCount', 'policySlots', 'policyCapacity',
  'policyExceptionSummary', 'policyConflictsPanel', 'policyConflicts', 'policyUnknownPanel',
  'policyUnknown', 'policyCompiledList', 'policyCompiledEmpty', 'policySampleResults',
  'policySamplesEmpty', 'policyExactDetails', 'policyExactSummary', 'policyExactList',
  'phoneRingOpen','phoneRingDialog','phoneRingConfirm','phoneRingCancel','phoneRingStatus',
  'autodialOpen','autodialDialog','autodialState','autodialRefresh','autodialNumber',
  'autodialSaveNumber','autodialTimeout','autodialSaveTimeout','autodialToggle',
  'autodialMessage','autodialClose','autodialConfirmDialog','autodialConfirmSummary',
  'autodialConfirmCancel','autodialConfirmApply',

  'historyPanel', 'historyLoadButton', 'historyClearButton', 'historyBlockNote', 'callAlertToggle', 'callAlertStatus', 'callAlertTest', 'callAlertLatest', 'historyClearAlert', 'historyStatus', 'historyError', 'historyList',
  'historyPager', 'historyPrevious', 'historyNext', 'historyPageStatus',
  'policyApplyButton', 'policyApplyHelp', 'policyApplyDialog', 'policyApplySummary',
  'policyApplyList', 'policyApplyProgress', 'policyApplyConfirm', 'policyApplyCancel',
  'policyApplyStop', 'policyApplyClose',
  'historySearch','historyType','historyPeriod','historySort','historyGroup','historyDates','historyFrom','historyTo','historyReset','historyTitle','missedCount',
  'busyBanner','busyTitle','busyDetail','busyElapsed','settingsOpen','settingsDialog','settingsTitle','settingsForm','routerIpInput','routerDetect','detectResult','settingsSave','settingsClose','settingsHint','settingsError','themeSelect','themeToggle',
  'workspaceNav','navCalls','navBlocks','navDNS','navActivity','navHelp','view-calls','view-blocks','view-dns','view-activity','view-help','legacyBlocksNotice','legacyBlocksWorkspace','legacyDnsNotice','legacyDnsSummary','modernDnsPanel','legacyActivityNotice','modernActivityPanel','simulatorOpen','simulatorDialog','simulatorClose','pageTitle','pageTitleIcon','pageTitleText','pageDescription','pageHeading','statusBar',
  'clearHistoryDialog','clearHistoryTitle','clearHistorySummary','clearHistoryStatus','clearHistoryError','clearHistoryCancel','clearHistoryConfirm',
  'dnsCurrentPrimary','dnsCurrentSecondary','dnsLastRead','dnsCapability','dnsRefresh','dnsStatus','dnsForm','dnsPrimary','dnsSecondary','dnsError','dnsPrepare','dnsLastOperation',
  'dnsModePanel','dnsModeCurrent','dnsModeStatic','dnsModeAuto','dnsRelayPanel','dnsRelayCheck','dnsRelayResult','dnsRelayDetails','dnsRelayInventory','dnsRelayInventoryMeta','dnsRelayInventoryList',
  'dnsReconcilePanel','dnsReconcileStatus','dnsReconcileInspect','dnsReconcileClose','dnsReconcileDialog','dnsReconcileTitle','dnsReconcileSummary','dnsReconcileCancel','dnsReconcileConfirm','dnsConfirmDialog','dnsConfirmTitle','dnsConfirmSummary','dnsConfirmError','dnsCancel','dnsCommit',
].map((id) => [id, $(id)]));

const model = {
  csrf: '', authenticated: false, legacy: null, serverBusy: false, state: null, operations: [],
  pending: 'boot', stale: true, uncertain: false, trackedOperation: null, submission: null,
  plan: null, planTimer: null, pollTimer: null, refreshTask: null, epoch: 0,
  lastFocus: null, inputTouched: false, disconnectFailed: false,
  sessionDeadline: 0, sessionTimer: null, localSessionTask: null, validatingSession: false,
  sessionReason: '', recovery: null, preparedIdentity: null, requests: new Set(),
  monitorDeadline: 0, monitorStopped: false, historyPage: 0,
  policyPreview: null, policyRevision: null, policyRowSequence: 0, policyVersion: 0,
  policyBatch: null,
  callHistory: null, historyError: '', historyAttempted:false, routerIp:'192.168.1.1', settingsCanChange:false,
  activeView:'calls', clearFlow:null, clearReview:false, clearPending:null,
  autodial:null,autodialPlan:null,
  advertisingNumbers:new Set(),
};
const DIGITS = /^[0-9]{1,32}$/;
 const NATIVE_PREFIX = /^[0-9]{3,8}x{1,6}$/;
 const isNativePrefix = value => typeof value === 'string' && value.length === 9 && NATIVE_PREFIX.test(value);
 const formattedCount = value => new Intl.NumberFormat('es-ES').format(value);
const icons = {
  phone: '<svg viewBox="0 0 20 20" fill="none" aria-hidden="true"><path d="m6.5 2 2 4-2 2a13 13 0 0 0 5.5 5.5l2-2 4 2c-.5 3-2 4.5-4.5 4.5C8 17 3 12 2 6.5 2 4 3.5 2.5 6.5 2Z"/></svg>',
  remove: '<svg viewBox="0 0 20 20" fill="none" aria-hidden="true"><path d="M4 5.5h12M8 3h4l1 2.5M6 5.5 7 17h6l1-11.5M8.5 8.5v5M11.5 8.5v5"/></svg>',
};


// UI-ICONS-TOAST-20261028: bundled, accessible SVG icons; no external dependencies.
const ACTION_PATHS = Object.freeze({
  sun:'<circle cx="12" cy="12" r="4"/><path d="M12 2v2m0 16v2M4.93 4.93l1.42 1.42m11.3 11.3 1.42 1.42M2 12h2m16 0h2M4.93 19.07l1.42-1.42m11.3-11.3 1.42-1.42"/>',
  moon:'<path d="M20.5 13.2A8.8 8.8 0 0 1 10.8 3.5 8.8 8.8 0 1 0 20.5 13.2Z"/>',
  settings:'<path d="M10.2 2h3.6l.6 2.3 2 .8 2.1-1.1 2.5 2.5-1.1 2.1.8 2L23 11v3l-2.3.6-.8 2 1.1 2.1-2.5 2.5-2.1-1.1-2 .8-.6 2.3h-3.6l-.6-2.3-2-.8-2.1 1.1L3 18.7l1.1-2.1-.8-2L1 14v-3l2.3-.6.8-2L3 6.3l2.5-2.5 2.1 1.1 2-.8z" transform="translate(0 -0.5) scale(.96)"/><circle cx="12" cy="12" r="3"/>',
  power:'<path d="M12 2v10"/><path d="M6.2 5.3a9 9 0 1 0 11.6 0"/>',
  refresh:'<path d="M20 7v5h-5M4 17v-5h5"/><path d="M5.6 9a7 7 0 0 1 12.5-2l1.9 5M4 12l1.9 5A7 7 0 0 0 18.5 15"/>',
  shield:'<path d="m12 2 8 3v7c0 5-3 8-8 10-5-2-8-5-8-10V5z"/><path d="m9 12 2 2 4-4"/>',
  shieldPlus:'<path d="m12 2 8 3v7c0 5-3 8-8 10-5-2-8-5-8-10V5z"/><path d="M12 8v8m-4-4h8"/>',
  check:'<path d="m5 12 4 4L19 6"/>',
  trash:'<path d="M4 6h16M9 3h6l1 3M6.5 6l1 15h9l1-15M10 10v7m4-7v7"/>',
  cancel:'<path d="M5 5 19 19M19 5 5 19"/>',
  calculator:'<rect x="5" y="2.5" width="14" height="19" rx="2"/><rect x="8" y="5.5" width="8" height="4" rx=".4"/><path d="M8.5 13h1m5 0h1m-7 4h1m5 0h1"/>',
  plus:'<path d="M12 5v14M5 12h14"/>',
  left:'<path d="m15 18-6-6 6-6"/>',
  right:'<path d="m9 18 6-6-6-6"/>',
  undo:'<path d="M9 14 4 9l5-5"/><path d="M4 9h10a6 6 0 0 1 0 12h-2"/>',
  save:'<path d="M4 3h14l3 3v15H3V3z"/><path d="M7 3v7h10V3M7 21v-8h10v8"/>',
  target:'<circle cx="12" cy="12" r="9"/><circle cx="12" cy="12" r="5"/><circle cx="12" cy="12" r="1"/>',
  stop:'<rect x="5" y="5" width="14" height="14" rx="2"/>',
  phone:'<path d="m6 3 3 4-2 2c2 4 4 6 8 8l2-2 4 3c-1 3-3 4-5 3C9 19 5 15 3 8c-1-2 0-4 3-5Z"/>',
  list:'<path d="M9 6h12M9 12h12M9 18h12M4 6h.01M4 12h.01M4 18h.01"/>',
  spark:'<path d="M12 2 9 9l-7 3 7 3 3 7 3-7 7-3-7-3-3-7Z"/>',
  activity:'<path d="M3 12h4l3-7 4 14 3-7h4"/>',
  help:'<circle cx="12" cy="12" r="9"/><path d="M9.5 9a2.5 2.5 0 0 1 5 0c0 2-2.5 2-2.5 4"/><path d="M12 17h.01"/>',
  search:'<circle cx="11" cy="11" r="7"/><path d="m16 16 5 5"/>',
  calendar:'<rect x="3" y="5" width="18" height="16" rx="2"/><path d="M7 3v4M17 3v4M3 10h18"/>',
  sort:'<path d="M8 3v18m0-18L4 7m4-4 4 4M16 21V3m0 18-4-4m4 4 4-4"/>',
  layers:'<path d="m12 2 9 5-9 5-9-5 9-5Zm-9 10 9 5 9-5M3 17l9 5 9-5"/>',
  mobile:'<rect x="6.5" y="2" width="11" height="20" rx="2"/><path d="M10 18h4"/>',
  megaphone:'<path d="M3 10h4l11-6v16L7 14H3v-4Zm4 4 2 7h4l-3-6M19 9l3-2m-3 8 3 2"/>',
  bell:'<path d="M18 8a6 6 0 0 0-12 0c0 7-3 7-3 9h18c0-2-3-2-3-9ZM10 21h4"/>',
  bellOff:'<path d="m3 3 18 18M18 8a6 6 0 0 0-11-3M6 9c0 6-3 6-3 8h14m-7 4h4"/>'
});
function actionIcon(name) {
  if (!Object.hasOwn(ACTION_PATHS,name)) throw Error('Unknown UI icon');
  const svg=document.createElementNS('http://www.w3.org/2000/svg','svg');
  svg.setAttribute('viewBox','0 0 24 24');svg.setAttribute('fill','none');
  svg.setAttribute('stroke','currentColor');svg.setAttribute('stroke-width','1.8');
  svg.setAttribute('stroke-linecap','round');svg.setAttribute('stroke-linejoin','round');
  svg.setAttribute('aria-hidden','true');svg.classList.add('action-icon');
  svg.innerHTML=ACTION_PATHS[name];return svg;
}
function setActionButton(element,label,icon,{iconOnly=false}={}) {
  const caption=String(label);
  if (element.dataset.actionIcon===icon && element.dataset.actionLabel===caption
    && element.classList.contains('button-icon-only')===iconOnly) return;
  const span=make('span',iconOnly?'sr-only':'button-caption',caption);
  element.replaceChildren(actionIcon(icon),span);
  element.classList.toggle('button-icon-only',iconOnly);
  element.dataset.actionIcon=icon;element.dataset.actionLabel=caption;
  if (iconOnly) {element.setAttribute('aria-label',caption);element.title=caption;}
  else {element.removeAttribute('title');element.removeAttribute('aria-label');}
}
function decorateStaticButtons(){
  const buttons={
    settingsOpen:['Configuración','settings'],refreshButton:['Actualizar','refresh'],
    callAlertToggle:['Avisarme de llamadas registradas','bell'],callAlertTest:['Probar notificación','bell'],
    phoneRingOpen:['Iniciar prueba','phone'],
    autodialOpen:['Configurar','settings'],autodialRefresh:['Actualizar estado','refresh'],
    autodialSaveNumber:['Guardar número','save'],autodialSaveTimeout:['Guardar espera','save'],
    autodialToggle:['Activar automarcado','power'],autodialClose:['Cerrar','cancel'],
    autodialConfirmCancel:['Cancelar','cancel'],autodialConfirmApply:['Confirmar cambio','check'],
    phoneRingCancel:['Cancelar','cancel'],phoneRingConfirm:['Hacer sonar teléfonos','bell'],
    historyClearButton:['Vaciar registro','trash'],clearHistoryCancel:['Cancelar','cancel'],clearHistoryConfirm:['Sí, vaciar todo el registro','trash'],
    connectButton:['Conectar al router','right'],reviewRefreshButton:['Actualizar y revisar','refresh'],
    historyLoadButton:['Consultar llamadas','phone'],historyReset:['Restablecer filtros','undo'],
    historyPrevious:['Anterior','left'],historyNext:['Siguiente','right'],
    addButton:['Revisar bloqueo','shieldPlus'],
    policyAddBlockButton:['Añadir condición','plus'],policyExampleButton:['Cargar ejemplo','spark'],policyPreviewButton:['Calcular propuesta','calculator'],
    policyApplyButton:['Revisar aplicación','shield'],
    policyApplyCancel:['Cancelar','cancel'],policyApplyConfirm:['Confirmar aplicación','shield'],
    policyApplyStop:['Detener tras la actual','stop'],policyApplyClose:['Cerrar y revisar lista','check'],
    routerDetect:['Autodetectar IP del router','target'],
    settingsClose:['Cerrar','cancel'],settingsSave:['Guardar IP','save'],
    dnsModeStatic:['Guardar DNS','save'],dnsRefresh:['Actualizar','refresh'],
    dnsModeAuto:['Usar DNS automáticas','undo'],
    cancelPlanButton:['Cancelar','cancel'],commitButton:['Confirmar bloqueo','shield']
  };
  for (const [id,[label,icon]] of Object.entries(buttons)) setActionButton(ui[id],label,icon);
}
decorateStaticButtons();
// Labels retain their text, association and keyboard focus target.
for(const [id,name] of Object.entries({
  historySearch:'search',historyType:'list',
  historyPeriod:'calendar',historySort:'sort',historyGroup:'layers'
})){
  const label=document.querySelector('label[for="'+id+'"]');
  if(label){
    label.classList.add('history-label-with-icon');
    label.prepend(actionIcon(name));
  }
}


class ApiError extends Error {
  constructor(message, code = 'REQUEST_FAILED', status = 0) {
    super(message); this.code = code; this.status = status;
  }
}

function rememberPendingIdentity(planId, operationId = null) {
  if (typeof planId !== 'string' || !planId) return;
  // These opaque identifiers are enough to find the durable receipt after login.
  // Telephone numbers, credentials and lists must not survive a privacy reset.
  model.recovery = {planId, operationId: typeof operationId === 'string' ? operationId : null};
}
function updateSessionDeadline(expiresAt, serverTime) {
  const expiry = Date.parse(expiresAt), clock = Date.parse(serverTime);
  if (!Number.isFinite(expiry) || !Number.isFinite(clock)) return;
  model.sessionDeadline = Date.now() + Math.max(0, expiry - clock);
  clearTimeout(model.sessionTimer);
  model.sessionTimer = null;
  if (model.authenticated) model.sessionTimer = setTimeout(() => {
    if (model.authenticated && Date.now() >= model.sessionDeadline) {
      invalidateSession('expired', 'La sesión ha caducado. Los datos se han retirado de la pantalla. Conecta de nuevo para continuar.');
    }
  }, Math.max(0, Math.min(model.sessionDeadline - Date.now(), 2147483000)));
}
async function ensureLocalSession() {
  if (model.localSessionTask) return model.localSessionTask;
  const epoch = model.epoch;
  const task = (async () => {
    try {
      const session = await api('/api/session');
      if (epoch !== model.epoch) return;
      if (!session || typeof session.csrf !== 'string' || !session.csrf) throw new ApiError('No se puede recuperar la sesión local.', 'INVALID_SESSION');
      model.csrf = session.csrf;
      updateSessionDeadline(session.expiresAt, session.serverTime);
      render();
    } catch (error) {
      if (epoch === model.epoch) {
        notice('No se puede comprobar la sesión local. Cuando vuelva la conexión podrás conectar de nuevo.', 'warning');
        render();
      }
    }
  })();
  model.localSessionTask = task;
  void task.finally(() => { if (model.localSessionTask === task) model.localSessionTask = null; });
  return task;
}
function invalidateSession(reason, message, {recover = true} = {}) {
  const pending = !!(model.recovery || model.submission || model.trackedOperation);
  clearSessionView();
  model.csrf = '';
  model.pending = '';
  model.disconnectFailed = false;
  model.validatingSession = false;
  model.sessionReason = reason;
  notice(message + (pending ? ' La operación enviada se conserva en el gestor; su recibo se comprobará al reconectar y no se repetirá.' : ''), 'warning');
  render();
  announce(message);
  if (recover && navigator.onLine !== false) void ensureLocalSession();
}
function stopAutomaticMonitoring(message) {
  stopPolling();
  model.monitorStopped = true;
  model.stale = true;
  if (model.recovery || model.submission || model.trackedOperation) model.uncertain = true;
  notice(message, 'warning');
  render();
}
// A fresh browser may issue overlapping local-session reads before a cookie
// is stored. Share that GET within the current UI epoch so its CSRF token
// cannot be paired with a different Set-Cookie response.
let inFlightLocalSession = null;
function api(resource, options = {}) {
  if (resource !== '/api/session' || (options.method && options.method !== 'GET'))
    return apiRequest(resource, options);
  const epoch = model.epoch;
  if (inFlightLocalSession?.epoch === epoch) return inFlightLocalSession.promise;
  const entry = {epoch, promise: apiRequest(resource, options)};
  inFlightLocalSession = entry;
  const clear = () => { if (inFlightLocalSession === entry) inFlightLocalSession = null; };
  void entry.promise.then(clear, clear);
  return entry.promise;
}
async function apiRequest(resource, { method = 'GET', body, monitor = false } = {}) {
  const headers = { Accept: 'application/json' };
  if(monitor && method === 'GET' && resource === '/api/calls')
    headers['X-Rearouter-Monitor']='1';
  const epoch = model.epoch;
  const commitPlanId = resource === '/api/commit' && method === 'POST' && typeof body?.planId === 'string' ? body.planId : null;
  if (method === 'POST') {
    if (!model.csrf) throw new ApiError('Actualiza la conexión antes de continuar.', 'NO_SESSION');
    headers['Content-Type'] = 'application/json';
    headers['X-Rearouter-CSRF'] = model.csrf;
  }
  if (resource === '/api/commit' && method === 'POST') {
    const identity = model.preparedIdentity?.planId === body?.planId ? model.preparedIdentity : null;
    rememberPendingIdentity(body?.planId, identity?.operationId || model.trackedOperation);
    model.monitorDeadline = Date.now() + REQUEST_BUDGETS.operationMs + REQUEST_BUDGETS.requestMs;
    model.monitorStopped = false;
  }
  const controller = new AbortController();
  const request = {controller, resource, epoch, endedBySession: false};
  model.requests.add(request);
  const timeout = setTimeout(() => controller.abort(), requestBudget(resource));
  try {
    const response = await fetch(resource, {
      method, headers, credentials: 'same-origin', mode: 'same-origin', redirect: 'error',
      cache: 'no-store', signal: controller.signal,
      ...(method === 'POST' ? { body: JSON.stringify(body ?? {}) } : {}),
    });
    let data;
    try { data = await response.json(); }
    catch {
      if (response.status === 401) data = null;
      else throw new ApiError('El gestor ha devuelto una respuesta que no se puede comprobar.', 'INVALID_RESPONSE', response.status);
    }
    const rejection = commitPlanId && !response.ok && data?.error?.commitAccepted === false
      ? Object.assign(new ApiError(data.error.message || 'El gestor no ha aceptado el envío.', data.error.code || 'REQUEST_FAILED', response.status), {rejectedPlanId: commitPlanId})
      : null;
    // Only a confirmed rejection of this exact one-shot request may cross a
    // session boundary. It carries no state, credentials or session headers.
    if (epoch !== model.epoch) {
      if (rejection) throw rejection;
      throw new ApiError('La sesión cambió durante la solicitud.', 'SESSION_CHANGED');
    }
    if (response.status === 401) {
      const code = data?.error?.code || 'NOT_AUTHENTICATED';
      const message = code === 'AUTH_FAILED' || code === 'AUTH_USER'
        ? data?.error?.message || 'No se ha podido autenticar con el router.'
        : 'La sesión ha caducado o ya no está autenticada. Conecta de nuevo para continuar.';
      invalidateSession('expired', message);
      throw rejection || new ApiError(message, code, 401);
    }
    updateSessionDeadline(response.headers.get('X-Rearouter-Session-Expires-At'), response.headers.get('X-Rearouter-Server-Time'));
    if (!response.ok) {
      const failure = rejection || new ApiError(data?.error?.message || 'No se ha podido completar la solicitud.', data?.error?.code || 'REQUEST_FAILED', response.status);
      // A 403 by itself does not establish cookie blocking. Only the server's
      // fixed-classification header can identify its rejected guard.
      const guard = response.status === 403 && data?.error?.code === 'FORBIDDEN'
        ? response.headers.get('X-Rearouter-Guard') : null;
      if (['CSRF','ORIGIN','HOST','FETCH_SITE'].includes(guard)) failure.localGuard = guard;
      throw failure;
    }
    if (resource === '/api/plan' && data?.planId && data?.operationId) {
      model.preparedIdentity = {planId: data.planId, operationId: data.operationId};
    }
    return data;
  } catch (error) {
    if (error instanceof ApiError) throw error;
    if (epoch !== model.epoch || request.endedBySession) throw new ApiError('La sesión cambió durante la solicitud.', 'SESSION_CHANGED');
    const timedOut = error.name === 'AbortError';
    if (resource === '/api/commit' && model.authenticated) {
      // A missing commit acknowledgement does not establish that the session
      // ended. Mask private data until the existing GET-only recovery checks it.
      model.validatingSession = true;
      render();
      try {
        const session = await api('/api/session');
        if (epoch !== model.epoch) throw new ApiError('La sesión cambió durante la comprobación.', 'SESSION_CHANGED');
        if (!session.authenticated) {
          invalidateSession('expired', 'La sesión ha terminado. La operación enviada se comprobará al reconectar.');
          throw new ApiError('La sesión ha terminado.', 'SESSION_CHANGED');
        }
        acceptSession(session);
        render();
      } catch {
        if (epoch === model.epoch) invalidateSession('connection', 'No se puede comprobar la sesión tras perderse la respuesta. Los datos se han retirado de la pantalla.', {recover: false});
        // This was a session probe, not a confirmed rejection of the commit.
        // Keep its receipt identity even when the probe itself returned 401.
        throw new ApiError('La sesión no se puede comprobar.', 'SESSION_CHANGED');
      }
    } else if (!timedOut && (resource !== '/api/session' || model.authenticated)) {
      invalidateSession('connection', 'Se ha perdido la comunicación con el gestor. Los datos se han retirado hasta comprobar la sesión.', {recover: false});
    }
    throw new ApiError(
      timedOut ? 'El gestor no ha respondido dentro del plazo previsto. La cancelación de la espera no confirma el resultado del trabajo.' : 'No se puede contactar con el gestor local.',
      timedOut ? 'TIMEOUT' : 'NETWORK_ERROR',
    );
  } finally { clearTimeout(timeout); model.requests.delete(request); }
}

function text(element, value) {
  const next = String(value ?? '');
  if (element.textContent !== next) element.textContent = next;
}
function make(tag, className, value) {
  const element = document.createElement(tag);
  if (className) element.className = className;
  if (value !== undefined) element.textContent = value;
  return element;
}
let noticeTimer = null;
function notice(message = '', tone = 'info') {
  clearTimeout(noticeTimer); noticeTimer = null;
  const value = String(message || '').trim();
  ui.notice.hidden = !value;
  ui.notice.className = 'notice' + (tone === 'info' ? '' : ' is-' + tone);
  // Errors announce immediately; successes and progress remain polite.
  ui.notice.setAttribute('role',tone === 'error' ? 'alert' : 'status');
  ui.notice.setAttribute('aria-live',tone === 'error' ? 'assertive' : 'polite');
  text(ui.noticeText, value);
  if (!value) return;
  const icon = tone === 'error' ? 'cancel' : tone === 'warning' ? 'target' : 'check';
  ui.noticeIcon.replaceChildren(actionIcon(icon));
  // An uncertain commit remains recorded in the persistent review banner and journal.
  ui.notice.style.animation = 'none'; void ui.notice.offsetWidth;
  ui.notice.style.animation = '';
  noticeTimer = setTimeout(() => {
    ui.notice.hidden = true; text(ui.noticeText,''); noticeTimer = null;
  }, 3000);
}
function announce(message) { text(ui.announcer, message); }
function statusOf(operation) {
  const status = String(operation?.status ?? '').toLowerCase().replace(/[\s_-]/g, '');
  if (operation?.reviewRequired === true || ['unknown', 'reviewrequired', 'requiresreview', 'uncertain', 'indeterminate'].includes(status)) return 'review';
  if (['running', 'queued', 'pending', 'inprogress', 'started'].includes(status)) return 'running';
  if (['completed', 'complete', 'succeeded', 'success', 'done'].includes(status)) return 'success';
  if (['failed', 'failure', 'error', 'cancelled', 'canceled', 'rejected'].includes(status)) return 'failed';
  return 'review';
}
function running() { return model.serverBusy || model.operations.some((operation) => statusOf(operation) === 'running'); }
function latestNeedsReview() { return !!model.operations[0] && statusOf(model.operations[0]) === 'review'; }
function needsReview() { return model.uncertain || latestNeedsReview(); }
function canWrite(type='add') {
  const allowed=type==='delete'?(model.state?.canDelete??model.state?.canWrite):
    (model.state?.canAdd??model.state?.canWrite);
  return model.authenticated&&!model.validatingSession&&!model.monitorStopped&&
    allowed===true&&!model.stale&&!model.pending&&!running()&&!needsReview();
}
function numericRule(rule) { return rule.exact === true && typeof rule.pattern === 'string' && DIGITS.test(rule.pattern); }
function patternDisplay(pattern) {
  return DIGITS.test(pattern) ? pattern : JSON.stringify(pattern).replace(/[\u007f-\u009f\u2028-\u202e\u2066-\u2069]/g, (character) => `\\u${character.charCodeAt(0).toString(16).padStart(4, '0')}`);
}
function dateLabel(value, withDate = false) {
  const date = new Date(value);
  if (!Number.isFinite(date.getTime())) return 'Hora no disponible';
  return new Intl.DateTimeFormat('es-ES', {
    ...(withDate ? { day: '2-digit', month: '2-digit' } : {}),
    hour: '2-digit', minute: '2-digit', ...(withDate ? {} : { second: '2-digit' }),
  }).format(date);
}
function validState(state) {
  return state && (state.lineNumber == null || (typeof state.lineNumber === 'string' && /^\+34[89][0-9]{8}$/.test(state.lineNumber))) && Array.isArray(state.incoming) && typeof state.canWrite === 'boolean' &&
    state.incoming.every((rule) => rule && typeof rule.id === 'string' && typeof rule.pattern === 'string' && typeof rule.exact === 'boolean') &&
    Array.isArray(state.warnings) && Number.isFinite(new Date(state.capturedAt).getTime());
}
function acceptState(state) {
  if (!validState(state)) throw new ApiError('La lista recibida no se puede validar. Actualiza antes de hacer cambios.', 'INVALID_STATE');
  if (model.policyPreview && model.policyRevision !== state.revision) clearPolicyResult('La lista del router ha cambiado. Calcula de nuevo la propuesta.');
  model.state = state;
  model.stale = false;
}
function mergeOperation(operation) {
  if (!operation || typeof operation.id !== 'string' || !operation.id) throw new ApiError('No se puede identificar el resultado de la operación.', 'INVALID_OPERATION');
  model.operations = [operation, ...model.operations.filter((item) => item.id !== operation.id)];
}
function correlateSubmission() {
  if (!model.submission && model.recovery) {
    const recovered = model.operations.filter(operation =>
      (model.recovery.operationId && operation.id === model.recovery.operationId) || operation.planId === model.recovery.planId);
    if (recovered.length === 1) {
      const operation = recovered[0];
      model.submission = {planId: operation.planId, type: operation.type, pattern: operation.pattern, ruleId: operation.ruleId};
      model.trackedOperation = operation.id;
    } else if (!model.serverBusy) model.uncertain = true;
  }
  if (!model.submission) return null;
  const matches = model.operations.filter((operation) =>
    (model.trackedOperation && operation.id === model.trackedOperation) ||
    operation.planId === model.submission.planId);
  if (matches.length === 1 && matches[0].type === model.submission.type && matches[0].pattern === model.submission.pattern &&
    (model.submission.type !== 'delete' || matches[0].ruleId === model.submission.ruleId)) {
    model.trackedOperation = matches[0].id;
    return statusOf(matches[0]) !== 'running' ? matches[0] : null;
  }
  if (!model.serverBusy) model.uncertain = true;
  return null;
}
function stopPolling() { clearTimeout(model.pollTimer); model.pollTimer = null; }
function schedulePoll() {
  stopPolling();
  if (!model.authenticated || model.legacy || model.monitorStopped || document.hidden) return;
  if (running()) {
    if (!model.monitorDeadline) model.monitorDeadline = Date.now() + REQUEST_BUDGETS.operationMs + REQUEST_BUDGETS.requestMs;
    if (Date.now() >= model.monitorDeadline) {
      stopAutomaticMonitoring('La comprobación automática ha alcanzado su plazo. El resultado sigue pendiente; pulsa Actualizar y revisar. No se reenviará ninguna operación.');
      return;
    }
    model.pollTimer = setTimeout(() => refreshDashboard({ quiet: true }), 2200);
  } else model.monitorDeadline = 0;
}

function clearPlan({ restoreFocus = true } = {}) {
  clearInterval(model.planTimer);
  model.planTimer = null;
  model.plan = null;
  model.preparedIdentity = null;
  if (ui.confirmDialog.open) ui.confirmDialog.close();
  text(ui.confirmNumber, '');
  text(ui.confirmSummary, '');
  text(ui.confirmError, '');
  ui.confirmError.hidden = true;
  if (restoreFocus) {
    const previous = model.lastFocus;
    const replacement = previous?.dataset?.ruleId
      ? [...ui.rulesList.querySelectorAll('button')].find((button) => button.dataset.ruleId === previous.dataset.ruleId)
      : previous?.dataset?.callNumber ? [...ui.historyList.querySelectorAll('button')].find(button=>button.dataset.callNumber===previous.dataset.callNumber) : null;
    const target = previous?.isConnected && !previous.disabled ? previous
      : replacement && !replacement.disabled ? replacement : ui.refreshButton;
    if (!target.disabled) target.focus();
  }
  model.lastFocus = null;
}
function clearSessionView() {
  if(ui.autodialConfirmDialog.open)ui.autodialConfirmDialog.close();
  if(ui.autodialDialog.open)ui.autodialDialog.close();
  model.autodial=null;model.autodialPlan=null;
  ui.autodialNumber.value='';ui.autodialTimeout.value='';
  if(ui.phoneRingDialog.open)ui.phoneRingDialog.close();
  if(ui.simulatorDialog.open)ui.simulatorDialog.close();
  if (!model.recovery && model.submission) rememberPendingIdentity(model.submission.planId, model.trackedOperation);
  model.epoch += 1;
  clearTimeout(model.sessionTimer); model.sessionTimer = null; model.sessionDeadline = 0;
  for (const request of model.requests) if (request.resource !== '/api/commit') { request.endedBySession = true; request.controller.abort(); }
  stopPolling();
  clearPlan({ restoreFocus: false });
  model.authenticated = false;
  model.legacy=null;
  model.serverBusy = false;
  model.state = null;
  model.operations = [];
  model.stale = true;
  model.uncertain = false;
  model.trackedOperation = null;
  model.submission = null;
  model.inputTouched = false;
  model.refreshTask = null; model.localSessionTask = null;
  model.monitorDeadline = 0; model.monitorStopped = false;
  ui.password.value = '';
  text(ui.lineNumber,'');ui.lineIdentity.hidden=true;
  ui.numberInput.value = '';
  ui.addMode.value = 'exact';
  ui.prefixPreview.hidden = true;
  ui.rulesList.replaceChildren();
  ui.activityList.replaceChildren();
  model.callHistory = null;
  model.advertisingNumbers.clear();
  stopCallNotifications();
  model.historyError = '';
  model.historyAttempted=false;
  model.clearFlow=null;model.clearReview=false;model.clearPending=null;
  model.activeView='calls';
  resetHistoryFilters();
  ui.historyList.replaceChildren();
  ui.policyExceptions.value = '';
  ui.policySamples.value = '';
  ui.policyBlocks.replaceChildren();
  model.policyRowSequence = 0;
  addPolicyBlock();
  clearPolicyResult();
  for (const id of ['policyCompiledList','policyConflicts','policyUnknown','policySampleResults','policyExactList','policyApplyList','policyApplySummary','policyApplyProgress']) ui[id].replaceChildren();
  if (model.policyBatch) model.policyBatch.stopRequested = true;
  model.policyBatch = null;
  if (ui.policyApplyDialog.open) ui.policyApplyDialog.close();
  if (ui.routerInfoDialog.open) ui.routerInfoDialog.close();
  ui.routerInfoLocal.replaceChildren();
  ui.routerInfoNetwork.replaceChildren();
  ui.routerInfoFunctions.replaceChildren();
  dnsUI.reset();
}

// The user's text can be a numeric stem or the entire nine-position native mask.
// Only this normalized mask is ever passed to the server, which revalidates it.
function validMaskInput(value) {
  return /^[0-9]{3,8}$/.test(value) || isNativePrefix(value);
}
function proposedAddPattern() {
  const input = ui.numberInput.value;
  return ui.addMode.value === 'prefix' && /^[0-9]{3,8}$/.test(input)
    ? input + 'x'.repeat(9 - input.length) : input;
}
function numberError() {
  const value = ui.numberInput.value;
  if (!value) return model.inputTouched ? 'Introduce el número o patrón que quieres bloquear.' : '';
  if (ui.addMode.value === 'prefix') {
    if (!validMaskInput(value)) return 'Escribe de 3 a 8 dígitos, o una máscara de nueve posiciones con x minúsculas al final (ej.: 123456xxx).';
  } else if (!DIGITS.test(value)) return 'Usa entre 1 y 32 dígitos, sin espacios ni comodines.';
  if (model.state?.incoming.some((rule) => rule.pattern === proposedAddPattern())) return 'Esta regla ya está en la lista.';
  return '';
}
function renderNumber() {
  const prefixMode = ui.addMode.value === 'prefix';
  text(ui.numberLabel, prefixMode ? 'Inicio del número o patrón completo' : 'Número de teléfono');
  text(ui.numberNote, prefixMode
    ? 'Introduce 3–8 dígitos (se completan con x) o la máscara completa de 9 posiciones. Cada x representa una posición variable. No se clasifica por país ni se aceptan otros formatos.'
    : 'De 1 a 32 dígitos, sin +, espacios ni comodines. Se conservan los ceros iniciales.');
  ui.numberInput.placeholder = prefixMode ? 'Ej.: 123456 o 123456xxx' : 'Número exacto';
  if (prefixMode) ui.numberInput.removeAttribute('pattern');
  else ui.numberInput.setAttribute('pattern', '[0-9]{1,32}');
  ui.numberInput.setAttribute('inputmode', prefixMode ? 'text' : 'numeric');
  const possible = prefixMode && validMaskInput(ui.numberInput.value);
  const mask = possible ? proposedAddPattern() : '';
  ui.prefixPreview.hidden = !possible;
  text(ui.prefixPreview, possible
    ? 'Patrón que se enviaría al router: ' + mask + '. Hasta ' +
      formattedCount(10 ** (9 - mask.indexOf('x'))) +
      ' números de nueve posiciones potencialmente coincidentes. Cobertura física de todas las terminaciones no demostrada.'
    : '');
  const error = numberError();
  text(ui.numberError, error);
  ui.numberError.hidden = !error;
  ui.numberInput.setAttribute('aria-invalid', error ? 'true' : 'false');
  ui.numberInput.disabled = !canWrite('add');
  ui.addMode.disabled = !canWrite('add');
  ui.addButton.disabled = !canWrite('add') || !!error || !ui.numberInput.value;
  text(ui.addButton.querySelector('span'), model.pending === 'plan-add' ? 'Preparando…' : 'Revisar bloqueo');
  let note = '';
  if (model.legacy) note = 'No disponible: este firmware no acredita bloqueo de llamadas. No se enviará ningún cambio.';
  else if (running()) note = 'Espera a que termine la operación en curso.';
  else if (needsReview()) note = 'Revisa el resultado de la última operación antes de hacer cambios.';
  else if (model.stale || !model.state) note = 'Actualiza la lista antes de hacer cambios.';
  else if (model.state.canAdd===false&&model.state.canDelete===true) note = 'Este firmware permite consultar y retirar reglas verificadas, pero no acreditar nuevas altas.';
  else if (model.state.canAdd===false) note = 'Este firmware no acredita nuevas altas. Las consultas verificables siguen disponibles.';
  else if (!model.state.canWrite) note = 'Los cambios están temporalmente desactivados. Revisa los avisos y actualiza el estado.';
  text(ui.writeNote, note);
  ui.writeNote.hidden = !note;
}

function renderRules() {
  const state = model.state;
  const legacy = !!model.legacy;
  const waiting = !state && !legacy;
  ui.rulesPanel.setAttribute('aria-busy', model.pending === 'refresh' || waiting ? 'true' : 'false');
  ui.rulesLoading.hidden = !waiting;
  ui.rulesUnavailable.hidden = !legacy;
  ui.rulesEmpty.hidden = legacy || !state || state.incoming.length !== 0;
  ui.rulesList.hidden = legacy || !state || state.incoming.length === 0;
  text(ui.ruleCount, legacy?'N/D':state ? state.incoming.length : '—');
  const fragment = document.createDocumentFragment();
  if (state) {
    for (const rule of state.incoming) {
      const row = make('li', 'rule-row');
      const identity = make('div', 'rule-identity');
      const icon = make('span', 'rule-phone-icon');
      icon.innerHTML = icons.phone;
      const details = make('div', 'rule-details');
      details.append(make('p', 'rule-number', patternDisplay(rule.pattern)));
      details.append(make('p', `rule-kind${numericRule(rule) ? '' : ' is-advanced'}`, numericRule(rule) ? 'Número exacto' : isNativePrefix(rule.pattern) ? 'Patrón de nueve posiciones · experimental' : 'Patrón existente · texto almacenado'));
      identity.append(icon, details);
      row.append(identity);
      if (rule.deletable === true) {
        const remove = make('button', 'remove-button');
        remove.type = 'button';
        remove.dataset.ruleId = rule.id;
        setActionButton(remove, 'Quitar', 'trash', {iconOnly:true});
        remove.setAttribute('aria-label', `Quitar la regla ${patternDisplay(rule.pattern)} de la lista de bloqueo`);
        remove.disabled = !canWrite('delete');
        remove.addEventListener('click', () => preparePlan({ type: 'delete', ruleId: rule.id, pattern: rule.pattern }, remove));
        row.append(remove);
      }
      fragment.append(row);
    }
  }
  ui.rulesList.replaceChildren(fragment);
  const outgoing = Number.isInteger(state?.outgoingCount) ? state.outgoingCount : '—';
  const profiles = Number.isInteger(state?.enabledProfiles) ? state.enabledProfiles : '—';
  text(ui.additionalConfig, state ? `${outgoing} ${outgoing === 1 ? 'regla saliente' : 'reglas salientes'} · ${profiles} ${profiles === 1 ? 'perfil activo' : 'perfiles activos'}` : ''); 
  if(legacy)text(ui.additionalConfig,'No disponible en este modelo');
  const sourceLabel=$('rulesReadSource');
  if(sourceLabel)text(sourceLabel,legacy?'No acreditado por el firmware':'Lectura directa del router');

}

function renderActivity() {
  text(ui.activityEmpty,model.legacy
    ? 'El historial de bloqueo no está disponible en este firmware. Consulta las acciones de telefonía en Llamadas.'
    : 'No hay operaciones para mostrar.');
  const visible = model.legacy ? [] : model.operations.slice(0, 10);
  ui.activityEmpty.hidden = visible.length !== 0;
  ui.activityList.hidden = visible.length === 0;
  text(ui.activityCount, visible.length ? `${visible.length} ${visible.length === 1 ? 'operación' : 'operaciones'}` : '');
  const fragment = document.createDocumentFragment();
  const labels = { running: 'En curso', success: 'Completada', failed: 'No completada', review: 'Revisar' };
  const symbols = { running: '↻', success: '✓', failed: '×', review: '!' };
  for (const operation of visible) {
    const kind = statusOf(operation);
    const row = make('li', 'activity-row');
    const icon = make('span', `activity-icon is-${kind}`, symbols[kind]);
    icon.setAttribute('aria-hidden', 'true');
    const copy = make('div', 'activity-copy');
    const action = operation.type === 'add' ? 'Añadir' : operation.type === 'delete' ? 'Quitar' : 'Operación sobre';
    copy.append(make('p', 'activity-title', `${action} ${String(operation.pattern ?? 'la lista')}`));
    if (operation.message) copy.append(make('p', `activity-message${kind === 'review' ? ' is-review' : ''}`, String(operation.message)));
    if (kind === 'review') copy.append(make('p', 'activity-message is-review', 'Actualiza y revisa la lista. No vuelvas a enviar esta operación.'));
    const time = make('time', 'activity-meta', dateLabel(operation.finishedAt || operation.createdAt, true));
    if (operation.finishedAt || operation.createdAt) time.dateTime = operation.finishedAt || operation.createdAt;
    copy.append(time);
    row.append(icon, copy, make('span', `operation-status is-${kind}`, labels[kind]));
    fragment.append(row);
  }
  ui.activityList.replaceChildren(fragment);
}


// The history view is initialized first: the opt-in call monitor receives
// its renderer but never owns history buttons or Livebox mutations.
const {resetHistoryFilters,renderCallHistory}=setupCallHistoryView({
  ui,model,make,text,actionIcon,setActionButton,
  running,dateLabel,canWrite,preparePlan,notice
});

// Inject only the existing UI/API dependencies; no new network requests.
const {state:callMonitor,stopCallNotifications,renderCallNotifications,
  toggleCallNotifications,restoreCallNotifications,acceptCallMonitorHistory,testCallNotification}=setupCallMonitor({
    ui,model,api,setActionButton,text,running,dateLabel,renderCallHistory,
    notice,announce,ApiError
  });

function legacyCanClear(){return model.legacy?.capabilities?.clearHistory===true;}
function renderClearAccess(){
  const flow=model.clearFlow;
  const unavailable=!model.authenticated||!model.callHistory||model.callHistory.total===0||
    model.pending||running()||model.disconnectFailed||model.clearReview||!!flow||
    model.state?.canClearHistory===false||(!!model.legacy&&!legacyCanClear());
  ui.historyClearButton.disabled=!!unavailable;
  ui.historyClearAlert.hidden=!model.clearReview;
  ui.clearHistoryCancel.disabled=!!flow?.polling;
  ui.clearHistoryConfirm.disabled=!flow||!!flow.submitted||!!model.pending||model.clearReview;
}
async function openClearHistory(){
  if(!model.authenticated||model.pending||running()||model.clearReview||
     model.clearFlow||!(model.callHistory?.total>0))return;
  const epoch=model.epoch;
  model.pending='history-clear-prepare';render();
  try {
    const plan=await api('/api/calls/clear/prepare',{method:'POST',body:{}});
    if(epoch!==model.epoch)return;
    if(typeof plan.token!=='string'||!Number.isInteger(plan.count)||plan.count<=0||
       !Number.isFinite(Date.parse(plan.expiresAt)))throw new ApiError('La preparación del borrado no es válida.');
    model.clearFlow={token:plan.token,expiresAt:plan.expiresAt,submitted:false,
      attemptId:null,polling:false};
    text(ui.clearHistorySummary,'Se borrarán TODAS las '+plan.count+
      ' llamadas registradas en el Livebox, incluidas las entrantes, salientes y perdidas. Los filtros no limitan el borrado. '+
      (model.legacy?'La configuración telefónica no cambia.':'Las reglas de bloqueo no cambian.'));
    text(ui.clearHistoryStatus,'Borrado preparado. Aún no se ha enviado nada al Livebox.');
    ui.clearHistoryError.hidden=true;
    model.pending='';render();
    ui.clearHistoryDialog.showModal();ui.clearHistoryCancel.focus();
  }catch(error){
    if(epoch!==model.epoch)return;
    notice('No se ha preparado el borrado: '+error.message,'error');
    model.pending='';render();
  }
}
function finishClearReview(message){
  model.clearReview=true;
  text(ui.clearHistoryStatus,message);
  notice('No se ha podido verificar el vaciado del registro. No repitas la operación.','warning');
  model.pending='';render();
  void syncClearReview();
}
// Local receipt only: shows a clear left in review after a reload or restart.
async function syncClearReview(){
  // A clear still in progress owns the dialog; a finished one may be in review.
  const busy=()=>model.clearFlow&&!model.clearReview;
  if(!model.authenticated||busy())return;
  const epoch=model.epoch;
  try{
    const status=await api('/api/calls/clear/status');
    if(epoch!==model.epoch||busy())return;
    model.clearPending=status?.review||null;
    model.clearReview=!!model.clearPending;
    render();
  }catch{}
}
// Reads the router only; the server never resends the clear.
async function reconcileClear(){
  const pending=model.clearPending;
  if(!model.authenticated||model.pending||running()||typeof pending?.id!=='string')return;
  const epoch=model.epoch;
  model.pending='history-clear-reconcile';render();
  try{
    const result=await api('/api/calls/clear/reconcile',{method:'POST',body:{attemptId:pending.id}});
    if(epoch!==model.epoch)return;
    const op=result?.attempt;
    if(result?.resolved===true&&op&&op.status!=='reviewRequired'){
      model.clearReview=false;model.clearPending=null;model.clearFlow=null;
      if(Array.isArray(result.history?.calls)){model.callHistory=result.history;model.historyPage=0;resetHistoryFilters();}
      notice(op.message||'Revisión cerrada.',op.status==='succeeded'?'success':'info');
      announce('Revisión del vaciado cerrada.');
    }else{
      model.clearPending=op||pending;
      notice(op?.lastCheck?.message||'El resultado sigue sin poder comprobarse. No se ha enviado nada.','warning');
    }
  }catch(error){
    if(epoch===model.epoch)notice('No se ha podido comprobar el resultado: '+error.message+' No se ha enviado nada al router.','error');
  }finally{
    if(epoch===model.epoch){model.pending='';render();}
  }
}
async function pollHistoryClear(flow,epoch){
  flow.polling=true;render();
  // The old firmware needs two native logins (send, then independent check).
  const expires=Date.now()+(model.legacy?180_000:90_000);
  try{
    while(epoch===model.epoch&&Date.now()<expires){
      const result=await api('/api/calls/clear/status');
      if(epoch!==model.epoch)return;
      const op=result?.attempt;
      if(!op||op.id!==flow.attemptId)throw new ApiError('El recibo del vaciado no coincide.');
      if(op.status==='succeeded') {
        model.callHistory={calls:[],total:0,truncated:false,capturedAt:new Date().toISOString()};
        if(callMonitor.enabled)callMonitor.snapshot=[];
        model.historyAttempted=true;model.historyError='';model.clearReview=false;
        model.clearFlow=null;model.pending='';resetHistoryFilters();
        if(ui.clearHistoryDialog.open)ui.clearHistoryDialog.close();
        render();notice('Registro de llamadas vaciado y verificado. '+
          (model.legacy?'La configuración telefónica se mantiene.':'Las reglas de bloqueo se mantienen.'), 'success');
        announce('Registro de llamadas vaciado correctamente.');return;
      }
      // Rejected before any POST: nothing to review, the history is intact.
      if(op.status==='failed'&&op.configurationPosts===0){
        model.clearFlow=null;model.pending='';
        if(ui.clearHistoryDialog.open)ui.clearHistoryDialog.close();
        render();notice('Borrado rechazado: '+(op.message||'no se ha enviado nada al Livebox.'),'error');
        return;
      }
      if(op.status==='failed'||op.status==='reviewRequired'){
        finishClearReview('Resultado incierto. '+(op.message||'No se ha podido verificar el vaciado. No se repetirá automáticamente.'));
        return;
      }
      text(ui.clearHistoryStatus,op.phase==='verifying'
        ?'Borrado enviado una sola vez. Verificando con una lectura independiente…'
        :op.phase==='dispatching'?'Reserva guardada. Enviando la orden única al Livebox…'
        :'Reservado una sola vez. Comprobando el historial antes de enviar…');
      await new Promise(resolve=>setTimeout(resolve,1200));
    }
    if(epoch===model.epoch)finishClearReview('La verificación ha agotado su plazo. Consulta el historial más tarde; no reenvíes el borrado.');
  }catch(error){
    if(epoch===model.epoch)finishClearReview('No se ha podido consultar el recibo. No se repetirá el borrado.');
  }finally{
    flow.polling=false;
    if(epoch===model.epoch)render();
  }
}
async function confirmClearHistory(){
  const flow=model.clearFlow;
  if(!flow||flow.submitted||model.pending||model.clearReview||!model.authenticated||
     Date.now()>=Date.parse(flow.expiresAt))return;
  flow.submitted=true;model.pending='history-clear';render();
  text(ui.clearHistoryStatus,'Solicitud única enviada. Esperando verificación…');
  try {
    const result=await api('/api/calls/clear/commit',{
      method:'POST',body:{token:flow.token,confirmation:'VACIAR_REGISTRO_COMPLETO'}});
    if(flow!==model.clearFlow)return;
    if(typeof result?.attempt?.id!=='string')throw new ApiError('El servidor no ha devuelto un recibo verificable.');
    flow.attemptId=result.attempt.id;
    await pollHistoryClear(flow,model.epoch);
  }catch(error){
    if(flow!==model.clearFlow)return;
    // Never retry a possibly delivered POST; query the local receipt once.
    try {
      const receipt=await api('/api/calls/clear/status');
      if(flow!==model.clearFlow)return;
      if(receipt?.attempt?.id && receipt.attempt.status!=='failed'){
        flow.attemptId=receipt.attempt.id;
        await pollHistoryClear(flow,model.epoch);return;
      }
    }catch{}
    if(flow===model.clearFlow)finishClearReview('El resultado del único envío no se puede demostrar. No vuelvas a pulsar Vaciar registro.');
  }
}
function cancelClearHistory(){
  const flow=model.clearFlow;
  if(flow?.polling||model.pending==='history-clear')return;
  if(ui.clearHistoryDialog.open)ui.clearHistoryDialog.close();
  if(!flow?.submitted)model.clearFlow=null;
  else if(!model.clearReview)model.clearReview=true;
  render();
}

async function loadCallHistory() {
  if (!model.authenticated || model.pending || running()) return;
  const epoch = model.epoch;
  model.historyAttempted=true;
  model.pending = 'call-history';
  model.historyError = '';
  render();
  try {
    const history = await api('/api/calls');
    if (epoch !== model.epoch) return;
    if (!history || !Array.isArray(history.calls) ||
        !Number.isInteger(history.total) || history.total<0 || history.calls.length>history.total ||
        (history.truncated!==undefined && typeof history.truncated!=='boolean') ||
        !Number.isFinite(Date.parse(history.capturedAt)) ||
        history.calls.some(item => !item || !['IN','MISS','OUT'].includes(item.type) ||
          typeof item.source !== 'string' || typeof item.destination !== 'string' ||
          typeof item.selectable !== 'boolean' || typeof item.dateTime !== 'string' || typeof item.duration !== 'string')) {
      throw new ApiError('El historial recibido no tiene un formato válido.', 'CALL_LOG_SCHEMA');
    }
    model.callHistory = history;
    if(model.legacy)model.legacy=withLegacyHistory(model.legacy,history);
    // A manual history refresh can be the first observer of a new call.
    const detected=callMonitor.enabled?acceptCallMonitorHistory(history):0;
    model.historyPage = 0;
    if(!detected){
      notice('Historial de llamadas actualizado.', 'success');
      announce('Llamadas cargadas. Los bloqueos requieren confirmar el número.');
    }
  } catch (error) {
    if (epoch !== model.epoch) return;
    model.historyError = error.message + (model.callHistory ? ' Se conserva la lectura anterior, cuya fecha figura debajo de los filtros.' : '');
  } finally {
    if (epoch === model.epoch) {
      model.pending = '';
      render();
      // Restore the saved opt-in only with a freshly loaded call-log baseline.
      // Not on the old firmware: each poll would be a native login.
      if(model.callHistory&&!model.legacy)restoreCallNotifications();
    }
  }
}

const workspaceIds={calls:['navCalls','view-calls'],blocks:['navBlocks','view-blocks'],
  dns:['navDNS','view-dns'],
  activity:['navActivity','view-activity'],help:['navHelp','view-help']};
const workspaceCopy={
  calls:['Llamadas','Consulta, filtra y gestiona el historial telefónico.'],
  blocks:['Bloqueos','Gestiona números exactos y prefijos; consulta el Simulador sin abandonar esta sección.'],
  dns:['DNS','Consulta y configuración DNS según las capacidades acreditadas del firmware.'],
  activity:['Actividad','Comprueba el resultado de las operaciones realizadas.'],
  help:['Ayuda','Guía de las secciones y operaciones del gestor.']
};
function renderViews(){
  const copy=workspaceCopy[model.activeView]||workspaceCopy.calls;
  text(ui.pageTitleText,copy[0]);text(ui.pageDescription,copy[1]);
  const headingIcon=model.activeView==='calls'?'phone':model.activeView==='blocks'?'shield':
    model.activeView==='dns'?'layers':
    model.activeView==='activity'?'activity':'help';
  if(ui.pageTitleIcon.dataset.icon!==headingIcon){
    ui.pageTitleIcon.replaceChildren(actionIcon(headingIcon));
    ui.pageTitleIcon.dataset.icon=headingIcon;
  }
  for(const [view,[tabId,panelId]] of Object.entries(workspaceIds)) {
    const selected=model.activeView===view;
    ui[tabId].setAttribute('aria-selected',selected?'true':'false');
    ui[tabId].tabIndex=selected?0:-1;
    ui[panelId].hidden=!selected;
  }
  // The legacy diagnostics belong only to the Calls workspace.
}
function selectView(view,{focusTab=false}={}) {
  if(!Object.hasOwn(workspaceIds,view))return;
  model.activeView=view;
  renderViews();
  if(view==='dns'&&!model.legacy)dnsUI.enter();
  if(focusTab)ui[workspaceIds[view][0]].focus();
}
for(const [view,[tabId]] of Object.entries(workspaceIds)) {
  ui[tabId].prepend(actionIcon(view==='calls'?'phone':view==='blocks'?'shield':view==='dns'?'layers':view==='activity'?'activity':'help'));
  ui[tabId].addEventListener('click',()=>selectView(view));
  ui[tabId].addEventListener('keydown',event=>{
    const names=Object.keys(workspaceIds),index=names.indexOf(view);
    const next=event.key==='ArrowRight'?names[(index+1)%names.length]:
      event.key==='ArrowLeft'?names[(index+names.length-1)%names.length]:
      event.key==='Home'?names[0]:event.key==='End'?names.at(-1):null;
    if(next){event.preventDefault();selectView(next,{focusTab:true});}
  });
}
function openSimulator() {
  if(!model.authenticated || ui.simulatorDialog.open)return;
  ui.simulatorDialog.showModal();
  ui.simulatorClose.focus();
}
ui.simulatorOpen.addEventListener('click',openSimulator);
ui.simulatorClose.addEventListener('click',()=>ui.simulatorDialog.close());
ui.simulatorDialog.addEventListener('close',()=>{
  if(model.authenticated && model.activeView==='blocks' && !ui.simulatorOpen.disabled)ui.simulatorOpen.focus();
});
// Compact, searchable help center. Search is strictly local to page text.
const helpSearch=document.getElementById('helpSearch');
const helpSearchClear=document.getElementById('helpSearchClear');
const helpSearchStatus=document.getElementById('helpSearchStatus');
const helpNoResults=document.getElementById('helpNoResults');
const helpArticles=Array.from(document.querySelectorAll('#helpArticles > details.help-article'));
const helpIndexButtons=Array.from(document.querySelectorAll('.help-index-link[data-help-section]'));
const helpNormalize=value=>String(value??'').normalize('NFD').replace(/[\u0300-\u036f]/g,'').toLocaleLowerCase('es-ES');
for(const slot of document.querySelectorAll('[data-help-icon]'))slot.replaceChildren(actionIcon(slot.dataset.helpIcon));
function syncHelpIndex(){
  for(const button of helpIndexButtons){
    const section=document.getElementById(button.dataset.helpSection);
    button.setAttribute('aria-controls',section.id);
    button.setAttribute('aria-expanded',section.open?'true':'false');
  }
}
function filterHelp({reset=false}={}){
  const query=helpNormalize(helpSearch.value.trim());
  let visible=0;
  for(const article of helpArticles){
    const match=!query||helpNormalize(article.textContent).includes(query);
    article.hidden=!match;
    if(query&&match)article.open=true;
    if(!query&&reset)article.open=article.id==='help-start';
    if(match)visible++;
  }
  for(const button of helpIndexButtons)button.hidden=document.getElementById(button.dataset.helpSection).hidden;
  helpSearchClear.hidden=!query;
  helpNoResults.hidden=visible!==0;
  helpSearchStatus.textContent=query?visible+' de '+helpArticles.length+' temas encontrados':helpArticles.length+' temas disponibles';
  syncHelpIndex();
}
helpSearch.addEventListener('input',()=>filterHelp({reset:!helpSearch.value.trim()}));
helpSearchClear.addEventListener('click',()=>{
  helpSearch.value='';
  filterHelp({reset:true});
  helpSearch.focus();
});
for(const button of helpIndexButtons)button.addEventListener('click',()=>{
  const section=document.getElementById(button.dataset.helpSection);
  if(section.hidden)return;
  for(const item of helpArticles)if(item!==section)item.open=false;
  section.open=true;
  syncHelpIndex();
  section.querySelector('summary').focus();
  section.scrollIntoView({block:'nearest'});
});
for(const article of helpArticles)article.addEventListener('toggle',()=>syncHelpIndex());
syncHelpIndex();
for(const btn of document.querySelectorAll('.help-go')) {
  const icon=btn.getAttribute('data-action-icon');
  // Reuse the existing local SVG registry; only these 5 known actions are valid.
  if(!['phone','shield','calculator','layers','activity'].includes(icon))
    throw Error('INVALID_HELP_ICON');
  setActionButton(btn,btn.textContent.trim(),icon);
  btn.addEventListener('click',()=>{
    const wantsSimulator=btn.dataset.openSimulator==='true';
    selectView(btn.dataset.helpTarget,{focusTab:!wantsSimulator});
    if(wantsSimulator)openSimulator();
  });
}

// Modal owns its own event handling and projections. The application only
// requests a render; router/ISP facts are kept separate in pure view models.
const {renderCompatibility}=setupRouterInfoDialog({
  ui,model,api,make,text,dateLabel,refreshLegacy
});
const dnsUI=setupDnsUI({ui,model,api,text,notice,render,running,needsReview,refreshLegacy});

// Only the initial session+state recovery uses the neutral boot screen.
// An unauthenticated result, timeout, or session loss always resolves to login.
let bootstrapResolved=false;
function render() {
  const authenticated = model.authenticated;
  const busy = running();
  const showAuthenticatedSections = bootstrapResolved && authenticated && !model.validatingSession;
  // Both sections are also hidden in the original HTML to prevent a
  // pre-login flash before app.js loads, including on a slow connection.
  const legacyVisible=showAuthenticatedSections&&!!model.legacy;
  ui.pageHeading.hidden = !showAuthenticatedSections;
  ui.statusBar.hidden = !showAuthenticatedSections;
  ui.bootView.hidden = bootstrapResolved;
  ui.connectionView.hidden = authenticated || !bootstrapResolved;
  // The login always displays the persisted destination, not an unsaved
  // candidate typed into the settings dialog.
  if(ui.connectionTargetIp.textContent!==model.routerIp)
    text(ui.connectionTargetIp,model.routerIp);
  ui.connectionTargetIp.setAttribute('aria-label',
    'Cambiar la IP de acceso al router, actualmente '+model.routerIp);
  ui.connectionTargetIp.disabled=!model.csrf||!!model.pending||running()||model.authenticated;
  ui.dashboard.hidden = !showAuthenticatedSections;
  // Same workspaces for both router families, with capability-driven
  // content; never route a legacy write to the modern firmware adapter.
  ui.workspaceNav.hidden=false;
  ui.dashboard.classList.toggle('legacy-firmware',legacyVisible);
  ui.legacyBlocksNotice.hidden=!legacyVisible;
  ui.legacyBlocksWorkspace.hidden=false;
  ui.legacyDnsNotice.hidden=!legacyVisible;
  ui.modernDnsPanel.hidden=false;
  ui.legacyActivityNotice.hidden=!legacyVisible;
  ui.modernActivityPanel.hidden=false;
  ui.simulatorOpen.disabled=legacyVisible;
  ui.simulatorOpen.title=legacyVisible?'Este firmware no ofrece bloqueo de llamadas.':'';
  if(legacyVisible){
    const v4=legacyDnsLabel(model.legacy,'ipv4');
    const v6=legacyDnsLabel(model.legacy,'ipv6');
    text(ui.legacyDnsSummary,'IPv4: '+v4+' · IPv6: '+v6);
  }
  ui.callAlertToggle.hidden=false;
  ui.historyClearButton.hidden=false;
  ui.historyBlockNote.hidden=false;
  text(ui.historyBlockNote,model.legacy?'El bloqueo de llamadas no está acreditado en este firmware.':
    'El icono de bloqueo abre una confirmación. Solo se bloquearán llamadas entrantes del número indicado, incluso al seleccionarlo desde una llamada saliente.');
  ui.confirmDialog.hidden = model.validatingSession;
  ui.policyApplyDialog.hidden = model.validatingSession;
  ui.disconnectButton.hidden = !bootstrapResolved || (!authenticated && !model.disconnectFailed);
  ui.disconnectButton.disabled = !!model.pending || busy;
  setActionButton(ui.disconnectButton, model.disconnectFailed ? 'Cerrar sesión pendiente' : model.pending === 'disconnect' ? 'Desconectando…' : 'Desconectar','power');
  ui.password.disabled = !model.csrf || !!model.pending || model.disconnectFailed || model.validatingSession;
  ui.connectButton.disabled = !model.csrf || !!model.pending || !ui.password.value || model.disconnectFailed || model.validatingSession;
  text(ui.connectButton.querySelector('span'), model.pending === 'connect' ? 'Conectando…' : 'Conectar al router');
  ui.refreshButton.disabled = !!model.pending || model.disconnectFailed;
  ui.refreshButton.classList.toggle('is-loading', ['boot', 'refresh','legacy-refresh'].includes(model.pending));
  ui.reviewRefreshButton.disabled = !!model.pending;
  ui.phoneRingOpen.disabled=!showAuthenticatedSections||!!model.pending||busy||model.monitorStopped||needsReview()||model.clearReview;
  ui.phoneRingConfirm.disabled=!!model.pending||busy||!showAuthenticatedSections;
  ui.autodialOpen.disabled=!showAuthenticatedSections||!!model.pending||busy||needsReview()||model.monitorStopped||model.clearReview;
  if(legacyVisible){
    ui.phoneRingOpen.disabled ||= model.legacy.capabilities?.ringTest!==true;
    ui.phoneRingConfirm.disabled ||= model.legacy.capabilities?.ringTest!==true;
    ui.autodialOpen.disabled ||= model.legacy.capabilities?.autodialRead!==true;
  }
  const ad=model.autodial, adWritable=!!ad&&!ad.reviewRequired&&showAuthenticatedSections&&!model.pending&&!busy&&
    (!legacyVisible||model.legacy.capabilities?.autodialWrite===true);
  ui.autodialRefresh.disabled=!!model.pending||!showAuthenticatedSections;
  ui.autodialNumber.disabled=!adWritable;
  ui.autodialTimeout.disabled=!adWritable;
  ui.autodialSaveNumber.disabled=!adWritable||ui.autodialNumber.value===ad.number||
    !/^[+*#0-9-]{1,32}$/.test(ui.autodialNumber.value);
  const sec=Number(ui.autodialTimeout.value);
  ui.autodialSaveTimeout.disabled=!adWritable||!Number.isInteger(sec)||sec<1||sec>10||sec===ad.seconds;
  ui.autodialToggle.disabled=!adWritable;
  if(ad){
    text(ui.autodialState,ad.reviewRequired?'Revisión necesaria: no repitas el cambio':
      (ad.enabled?'Activado':'Desactivado')+' · '+ad.seconds+' segundos');
    setActionButton(ui.autodialToggle,ad.enabled?'Desactivar automarcado':'Activar automarcado','power');
  }else text(ui.autodialState,'Sin consultar');

  let connectionText = 'Sin conexión · '+model.routerIp;
  if (model.validatingSession) connectionText = 'Comprobando la sesión local';
  else if (model.pending === 'boot') connectionText = 'Comprobando conexión';
  else if (model.pending === 'connect') connectionText = 'Conectando con el router';
  else if (authenticated) connectionText = model.monitorStopped ? 'Resultado pendiente de comprobar' : busy || model.pending === 'commit' ? 'Operación en curso' : 'Livebox · '+model.routerIp;
  else if (model.sessionReason === 'expired') connectionText = 'Sesión caducada';
  else if (model.sessionReason === 'connection' || model.sessionReason === 'offline') connectionText = 'Conexión sin verificar';
  else if (model.disconnectFailed) connectionText = 'Desconexión pendiente';
  text(ui.connectionText, connectionText);
  ui.connectionStatus.className = `connection-status${authenticated ? busy || model.pending === 'commit' ? ' is-busy is-pending' : '' : ' is-disconnected'}`;
  const capture=authenticated?(model.legacy?legacyCapturedAt(model.legacy):model.state?.capturedAt):null;
  text(ui.capturedTime, capture ? `Última lectura a las ${dateLabel(capture)}` : 'Sin lectura todavía');
  const legacyNumbers=legacyVisible&&legacyReadVerified(model.legacy,'phone')?
    [...new Set((model.legacy.phone?.lines||[]).map(line=>line.number).filter(number=>typeof number==='string'&&/^\+34[89][0-9]{8}$/.test(number)))]:[];
  const candidateLine=legacyVisible?(legacyNumbers.length===1?legacyNumbers[0]:null):model.state?.lineNumber;
  const fixedLine=showAuthenticatedSections&&typeof candidateLine==='string'&&/^\+34[89][0-9]{8}$/.test(candidateLine)?candidateLine:'';
  text(ui.lineNumber,fixedLine?fixedLine.replace(/^\+34/,'+34.'):'No verificada');
  ui.lineIdentity.hidden = !showAuthenticatedSections;
  if (capture) {
    ui.capturedTime.dateTime = capture;
    ui.capturedTime.title = dateLabel(capture, true);
  } else {
    ui.capturedTime.removeAttribute('datetime');
    ui.capturedTime.removeAttribute('title');
  }
  ui.reviewBanner.hidden = !authenticated || (!needsReview()&&!model.clearReview);
  setActionButton(ui.reviewRefreshButton,model.clearReview?'Comprobar resultado':'Actualizar y revisar','refresh');
  ui.reviewRefreshButton.classList.toggle('is-loading',model.pending==='history-clear-reconcile');
  text(ui.reviewTitle,model.clearReview?'El resultado del vaciado del historial necesita comprobación':'Revisa el resultado antes de continuar');
  text(ui.reviewText, model.clearReview ? (model.clearPending?.lastCheck?.message||
    'RuxBox+ puede comprobarlo leyendo el router, sin volver a enviar el vaciado.')+' Mientras tanto no se permiten otros cambios.' : model.uncertain
    ? 'No se ha podido confirmar el resultado del envío. Actualiza la lista y la actividad; la operación no se enviará de nuevo.'
    : 'La última operación necesita revisión. Comprueba la lista actual y su resultado antes de continuar; no la vuelvas a enviar.');
  const warnings = (model.state?.warnings || []).map((warning) => typeof warning === 'string' ? warning : warning?.message).filter(Boolean);
  ui.warningsPanel.hidden = warnings.length === 0;
  ui.warningsList.replaceChildren(...warnings.map((warning) => make('li', '', String(warning))));
  renderRules();
  renderNumber();
  renderActivity();
  renderCallHistory();
  renderClearAccess();
  renderCallNotifications();
  if(legacyVisible){
    ui.callAlertToggle.disabled=true;
    ui.callAlertToggle.title='Los avisos automáticos no están acreditados para este firmware.';
    text(ui.callAlertStatus,'Avisos automáticos no disponibles en este firmware. Consulta las llamadas manualmente.');
  }else ui.callAlertToggle.removeAttribute('title');
  renderViews();
  renderCompatibility();
  dnsUI.render();
  // The same DNS panel displays the older firmware's verified values read-only.
  if(legacyVisible){
    const dns=model.legacy.dns?.ipv4;
    const primary=dns?.connected&&typeof dns.primary==='string'?dns.primary:'';
    const secondary=dns?.connected&&typeof dns.secondary==='string'?dns.secondary:'';
    text(ui.dnsModeCurrent,legacyDnsLabel(model.legacy,'ipv4'));
    ui.dnsPrimary.value=primary;
    ui.dnsSecondary.value=secondary;
    ui.dnsPrimary.disabled=true;
    ui.dnsSecondary.disabled=true;
    ui.dnsModeStatic.disabled=true;
    ui.dnsModeAuto.disabled=true;
    ui.dnsRefresh.disabled=!!model.pending||busy;
    ui.dnsReconcilePanel.hidden=true;
    text(ui.dnsStatus,'Solo lectura: este firmware no acredita un formulario para cambiar las DNS WAN.');
  }
  renderPolicyAccess();
  renderBusy();
  renderSettingsAccess();
}

function acceptSession(session) {
  if (!session || typeof session.csrf !== 'string' || !session.csrf || typeof session.authenticated !== 'boolean') {
    throw new ApiError('No se ha podido establecer una sesión local válida.', 'INVALID_SESSION');
  }
  if(typeof session.routerIp==='string') model.routerIp=session.routerIp;
  model.csrf = session.csrf;
  model.authenticated = session.authenticated;
  // Only a sanitized diagnostic profile is accepted, never raw CGI or tokens.
  model.legacy = session.authenticated &&
    session.legacy?.family==='livebox-fibra-legacy'&&
    session.legacy?.readOnly===true&&session.legacy?.authentication==='VERIFIED'
    ? session.legacy : null;
  // The old router's history is read in the same native session as the rest
  // of its snapshot; a newer manual history read is never overwritten.
  const legacyHistory=model.legacy?.history;
  if(model.legacy)model.historyError=legacyReadVerified(model.legacy,'history')?'':
    legacyHistory?'No se pudo actualizar el historial. Se conserva la última lectura verificada.':'Historial no disponible en esta lectura.';
  if(legacyHistory&&Array.isArray(legacyHistory.calls)&&
     (!model.callHistory||Date.parse(legacyHistory.capturedAt)>Date.parse(model.callHistory.capturedAt))){
    model.callHistory=legacyHistory;model.historyAttempted=true;model.historyPage=0;
  }
  model.validatingSession = false;
  model.serverBusy = session.authenticated && !!session.busy;
  model.sessionReason = '';
  model.disconnectFailed = false;
  updateSessionDeadline(session.expiresAt, session.serverTime);
  if(model.authenticated)void syncClearReview();
}

async function refreshLegacy(){
  if(model.pending||!model.legacy)return;
  const epoch=model.epoch;
  model.pending='legacy-refresh';notice();render();
  try{
    await readLegacySession(epoch);
  }catch(error){
    if(epoch!==model.epoch)return;
    notice(error.message+' No se repetirá automáticamente.','error');
    // Recover only the LOCAL session. Never send a second native login.
    try{const session=await api('/api/session');if(epoch===model.epoch)acceptSession(session)}catch{}
  }finally{
    if(epoch===model.epoch){model.pending='';render();}
  }
}
async function readLegacySession(epoch){
  try{
    const session=await api('/api/legacy/refresh',{method:'POST',body:{}});
    if(epoch!==model.epoch)return;
    acceptSession(session);
    notice(legacyReadMessage(model.legacy),legacyReadStatus(model.legacy)==='COMPLETE'?'success':'warning');
  }catch(error){
    if(epoch===model.epoch&&model.legacy)model.legacy=legacyRefreshFailed(model.legacy,error.code||'NETWORK_ERROR');
    throw error;
  }
}

async function refreshDashboard({ quiet = false } = {}) {
  if (model.disconnectFailed) return;
  if (model.refreshTask) return model.refreshTask;
  if (model.pending && !['boot', 'refresh'].includes(model.pending)) return;
  const epoch = model.epoch;
  if (!quiet) { model.monitorStopped = false; model.monitorDeadline = 0; }
  model.pending = 'refresh';
  if (!quiet) notice();
  render();
  const task = (async () => {
    try {
      const session = await api('/api/session');
      if (epoch !== model.epoch) return;
      acceptSession(session);
      if (!model.authenticated) {
        const wasConnected = !!model.state;
        clearSessionView();
        model.pending = '';
        model.sessionReason = wasConnected ? 'expired' : model.sessionReason;
        if (wasConnected || model.recovery) notice('La sesión con el router ha terminado. Conecta de nuevo para continuar.' + (model.recovery ? ' Se conserva la identidad de la operación pendiente para recuperar su recibo sin reenviarla.' : ''), 'warning');
        render();
        return;
      }
      if(model.legacy){
        if(!quiet)await readLegacySession(epoch);
        return;
      }
      const data = await api('/api/operations');
      if (epoch !== model.epoch) return;
      if (!Array.isArray(data.operations)) throw new ApiError('No se puede comprobar la actividad reciente.', 'INVALID_OPERATIONS');
      model.operations = data.operations.filter((operation) => operation && typeof operation.id === 'string');
      if (!model.operations.length && session.lastOperation?.id) model.operations = [session.lastOperation];
      let resolved = correlateSubmission();
      if (!running()) {
        const reconciling = model.uncertain || latestNeedsReview();
        const state = await api('/api/state');
        if (epoch !== model.epoch) return;
        acceptState(state);
        if (reconciling) {
          const reconciled = await api('/api/operations');
          if (epoch !== model.epoch) return;
          if (!Array.isArray(reconciled.operations)) throw new ApiError('No se puede comprobar el resultado de la revisión.', 'INVALID_OPERATIONS');
          model.operations = reconciled.operations.filter((operation) => operation && typeof operation.id === 'string');
          resolved = correlateSubmission();
        }
        if (resolved) {
          const kind = statusOf(resolved);
          model.uncertain = kind === 'review';
          if (kind !== 'review') {
            model.trackedOperation = null;
            model.submission = null;
            model.recovery = null;
            if (kind === 'success') {
              const message = resolved.type === 'delete' ? 'Número retirado. La lista del router está actualizada.' : 'Número añadido. La lista del router está actualizada.';
              notice(message, 'success');
              announce(message);
            } else notice('La operación no se ha completado. Revisa su resultado en la actividad reciente.', 'error');
          }
        }
      }
      if (!quiet && !resolved) { notice('Lista de bloqueo actualizada.', 'success'); announce('Estado actualizado.'); }
    } catch (error) {
      if (epoch !== model.epoch) return;
      model.stale = true;
      notice(`${error.message} Actualiza para comprobar el estado antes de hacer cambios.`, 'error');
      if (model.trackedOperation || model.recovery) model.uncertain = true;
      if (['TIMEOUT','ROUTER_TIMEOUT','WORK_TIMEOUT','NETWORK_ERROR'].includes(error.code) || model.serverBusy) model.monitorStopped = true;
    } finally {
      const firstLoadCompleted=!bootstrapResolved;
      bootstrapResolved=true; // Never leave the neutral view stuck on failures or expiry.
      if (epoch === model.epoch) {
        model.pending = '';
        model.refreshTask = null;
        render();
        if(!model.legacy)schedulePoll();
        if(model.authenticated&&!model.legacy&&!running()&&!model.historyAttempted) void loadCallHistory();
      }else if(firstLoadCompleted){
        // /api/session may invalidate an expired session and advance epoch.
        // Reveal the login only after that rejection is final.
        render();
      }
    }
  })();
  model.refreshTask = task;
  return task;
}

async function connect(event) {
  event.preventDefault();
  if (model.pending || model.disconnectFailed) return;
  if (!ui.password.value) {
    text(ui.connectError, 'Introduce la contraseña de administración del router.');
    ui.connectError.hidden = false;
    ui.password.focus();
    return;
  }
  let password = ui.password.value;
  ui.password.value = '';
  const epoch = model.epoch;
  model.pending = 'connect';
  model.monitorStopped = false;
  model.sessionReason = '';
  ui.connectError.hidden = true;
  notice(); render();
  try {
    // The local cookie may have expired while the login form was idle.
    // Renew only this local session; never retry the router login automatically.
    const local = await api('/api/session');
    if (epoch !== model.epoch) return;
    model.csrf = local.csrf;
    let session;
    try {
      session = await api('/api/connect', {method: 'POST', body: {password}});
    } catch (error) {
      // FORBIDDEN is rejected by the local HTTP guard before the password is
      // parsed and before any router command. Only that definitive rejection
      // permits one renewed local-cookie/CSRF handshake. Never retry a router
      // authentication after an uncertain result, timeout, 401 or 5xx.
      if (error?.code !== 'FORBIDDEN' || error.status !== 403) throw error;
      // Only an identified CSRF mismatch can be retried, and only once.
      const guardMessages = {
        ORIGIN: 'El navegador envía un origen distinto del gestor (HTTP 403, ORIGIN). No se ha enviado la contraseña al router.',
        HOST: 'La dirección del servidor no coincide con la esperada (HTTP 403, HOST). No se ha enviado la contraseña al router.',
        FETCH_SITE: 'El navegador marca esta solicitud como procedente de otro sitio (HTTP 403, FETCH_SITE). No se ha enviado la contraseña al router.',
      };
      if (error.localGuard !== 'CSRF') {
        throw new ApiError(guardMessages[error.localGuard] ||
          'La solicitud local fue rechazada con HTTP 403 sin causa clasificada. No se ha enviado la contraseña al router.',
          'LOCAL_GUARD_'+(error.localGuard || 'UNKNOWN'), 403);
      }
      const renewed = await api('/api/session');
      if (epoch !== model.epoch) return;
      if (typeof renewed?.csrf !== 'string' || !renewed.csrf)
        throw new ApiError('No se ha podido renovar la sesión local.', 'INVALID_SESSION');
      model.csrf = renewed.csrf;
      try {
        session = await api('/api/connect', {method: 'POST', body: {password}});
      } catch (retryError) {
        if (retryError?.code === 'FORBIDDEN' && retryError.status === 403) {
          const reason = retryError.localGuard || 'UNKNOWN';
          const detail = reason === 'CSRF'
            ? 'El token CSRF no coincide con la sesión local incluso después de renovarlo.'
            : (guardMessages[reason] || 'La causa del segundo rechazo local no está clasificada.');
          throw new ApiError(detail+' (HTTP 403, '+reason+'). No se ha enviado la contraseña al router.',
            'LOCAL_GUARD_'+reason, 403);
        }
        throw retryError;
      }
    }
    password = null;
    if (epoch !== model.epoch) return;
    acceptSession(session);
    if (!model.authenticated) throw new ApiError('No se ha establecido la conexión con el router.', 'NOT_AUTHENTICATED');
    model.pending = '';
    if(model.legacy){
      bootstrapResolved=true;
      render();
      notice(legacyReadMessage(model.legacy),legacyReadStatus(model.legacy)==='COMPLETE'?'success':'warning');
      announce(legacyReadMessage(model.legacy));
      return;
    }
    notice('Conexión con el router establecida.', 'success');
    announce('Conexión establecida. Consultando la lista de bloqueo.');
    await refreshDashboard();
  } catch (error) {
    if (epoch !== model.epoch) return;
    text(ui.connectError, error.message); ui.connectError.hidden = false;
    model.authenticated = false; model.pending = '';
    render(); ui.password.focus();
  } finally { password = null; }
}

async function disconnect() {
  if (model.pending || running()) return;
  clearSessionView();
  const epoch = model.epoch;
  model.pending = 'disconnect';
  model.sessionReason = '';
  notice(); render();
  try {
    const local = await api('/api/session');
    if (epoch !== model.epoch) return;
    model.csrf = local.csrf;
    if (local.authenticated) await api('/api/disconnect', {method: 'POST', body: {}});
    if (epoch !== model.epoch) return;
    model.disconnectFailed = false;
    notice('Te has desconectado del router.', 'success');
  } catch (error) {
    // A session reset already owns the display. A late close cannot change a
    // newer login or turn an already expired session into a failed disconnect.
    if (epoch !== model.epoch) {
      if (error.code === 'NETWORK_ERROR' && model.epoch === epoch + 1 && model.sessionReason === 'connection') {
        model.disconnectFailed = true;
        notice(`${error.message} No se ha podido comprobar el cierre. Pulsa «Cerrar sesión pendiente» cuando vuelva la conexión.`, 'warning');
        render();
      }
      return;
    }
    model.disconnectFailed = true;
    notice(`${error.message} No se ha podido comprobar el cierre. Pulsa «Cerrar sesión pendiente» cuando vuelva la conexión.`, 'warning');
  } finally {
    if (epoch === model.epoch) {
      model.pending = ''; render();
      if (!model.disconnectFailed) { await ensureLocalSession(); if (epoch === model.epoch) ui.password.focus(); }
    }
  }
}

function updatePlanExpiry() {
  const plan = model.plan;
  if (!plan) return;
  const seconds = Math.max(0, Math.ceil((new Date(plan.expiresAt).getTime() - Date.now()) / 1000));
  const expired = seconds === 0;
  text(ui.confirmExpiry, model.pending === 'commit'
    ? 'Enviando una sola solicitud. Espera a que se compruebe el resultado…'
    : expired ? 'La confirmación ha caducado. Cierra este cuadro y prepara de nuevo el cambio.' : `Esta confirmación es válida durante ${seconds} ${seconds === 1 ? 'segundo' : 'segundos'}.`);
  ui.confirmExpiry.classList.toggle('is-expired', expired && model.pending !== 'commit');
  ui.commitButton.disabled = expired || !!model.pending || !canWrite(plan.type) || plan.submitted;
  ui.cancelPlanButton.disabled = model.pending === 'commit';
}

async function preparePlan(request, trigger) {
  if (!canWrite(request.type) || model.plan) return;
  if (request.type === 'add' && (!(DIGITS.test(request.pattern) || isNativePrefix(request.pattern)) || model.state.incoming.some((rule) => rule.pattern === request.pattern))) return;
  if (request.type === 'delete' && !model.state.incoming.some((rule) => rule.id === request.ruleId && rule.pattern === request.pattern && rule.deletable === true)) return;
  const epoch = model.epoch;
  model.pending = `plan-${request.type}`;
  model.lastFocus = trigger;
  notice();
  render();
  try {
    const plan = await api('/api/plan', { method: 'POST', body: request });
    if (epoch !== model.epoch) return;
    if (!plan || typeof plan.planId !== 'string' || !plan.planId || plan.type !== request.type || plan.pattern !== request.pattern ||
      (request.type === 'delete' && plan.ruleId !== request.ruleId) ||
      !Number.isFinite(new Date(plan.expiresAt).getTime()) || new Date(plan.expiresAt).getTime() <= Date.now()) {
      throw new ApiError('No se puede confirmar este cambio. Actualiza la lista y revisa sus datos.', 'INVALID_PLAN');
    }
    model.plan = { ...plan, submitted: false };
    model.pending = '';
    const deleting = plan.type === 'delete';
    ui.confirmDialog.classList.toggle('is-delete', deleting);
    text(ui.confirmTitle, deleting ? DIGITS.test(plan.pattern) ? '¿Quitar este número de la lista?' : '¿Quitar esta regla de la lista?' : isNativePrefix(plan.pattern) ? '¿Bloquear este patrón?' : '¿Bloquear este número?');
    text(ui.confirmNumber, patternDisplay(plan.pattern));
    text(ui.confirmSummary, typeof plan.summary === 'string' && plan.summary ? plan.summary : deleting
      ? 'Se quitará únicamente la regla seleccionada de la lista de bloqueo de llamadas entrantes.'
      : 'Se añadirá una regla de bloqueo para este número exacto. Revisa sus dígitos antes de confirmar.');
    setActionButton(ui.commitButton, deleting ? 'Confirmar retirada' : 'Confirmar bloqueo', deleting?'trash':'shield');
    ui.commitButton.className = `button ${deleting ? 'button-danger' : 'button-primary'}`;
    ui.confirmError.hidden = true;
    render();
    updatePlanExpiry();
    ui.confirmDialog.showModal();
    ui.cancelPlanButton.focus();
    model.planTimer = setInterval(updatePlanExpiry, 1000);
  } catch (error) {
    if (epoch !== model.epoch) return;
    model.pending = '';
    model.stale = true;
    notice(error.message, 'error');
    render();
    announce(error.message);
  }
}

async function commitPlan() {
  const plan = model.plan;
  if (!plan || plan.submitted || !canWrite(plan.type) || Date.now() >= new Date(plan.expiresAt).getTime()) return;
  const epoch = model.epoch;
  plan.submitted = true;
  model.submission = { planId: plan.planId, type: plan.type, pattern: plan.pattern, ruleId: plan.ruleId };
  model.trackedOperation = typeof plan.operationId === 'string' ? plan.operationId : null;
  model.pending = 'commit';
  model.stale = true;
  if (plan.type === 'add') { ui.numberInput.value = ''; model.inputTouched = false; }
  stopPolling();
  updatePlanExpiry();
  render();
  try {
    // A commit is sent exactly once. A timeout or uncertain response is followed only by reads.
    const result = await api('/api/commit', { method: 'POST', body: { planId: plan.planId } });
    if (epoch !== model.epoch) return;
    if (result.operation?.type !== plan.type || result.operation?.pattern !== plan.pattern ||
      (plan.type === 'delete' && result.operation?.ruleId !== plan.ruleId) ||
      (result.operation?.planId && result.operation.planId !== plan.planId)) {
      throw new ApiError('La respuesta no identifica el cambio que acabas de confirmar.', 'OPERATION_MISMATCH');
    }
    mergeOperation(result.operation);
    const kind = statusOf(result.operation);
    model.trackedOperation = result.operation.id;
    model.uncertain = kind === 'review';
    if (result.state && kind !== 'running') acceptState(result.state);
    notice(kind === 'running' ? 'Solicitud enviada. Comprobando el resultado…'
      : kind === 'success' ? 'Cambio confirmado. Actualizando la lista del router.'
      : kind === 'review' ? 'El resultado necesita revisión. La solicitud no se enviará de nuevo.'
      : 'La operación no se ha completado. Revisa su resultado en la actividad reciente.',
    kind === 'review' ? 'warning' : kind === 'failed' ? 'error' : kind === 'success' ? 'success' : 'info');
  } catch (error) {
    const rejected = error.rejectedPlanId === plan.planId;
    const rejectedCurrent = rejected && model.recovery?.planId === plan.planId;
    if (rejectedCurrent) model.recovery = null;
    if (epoch !== model.epoch) {
      if (rejectedCurrent && (!model.submission || model.submission.planId === plan.planId) &&
          (!model.trackedOperation || model.trackedOperation === plan.operationId)) {
        model.submission = null; model.trackedOperation = null; model.uncertain = false;
        if (!model.authenticated && !model.pending && model.sessionReason === 'expired')
          notice('El gestor ha confirmado que el intento pendiente no se aceptó. Conecta de nuevo para continuar.', 'warning');
        render();
      }
      return;
    }
    model.uncertain = !rejected;
    if (rejected) {
      model.submission = null; model.trackedOperation = null;
      notice(`${error.message} El gestor ha rechazado el envío. No se ha repetido.`, 'error');
    } else notice(`${error.message} El resultado del envío es incierto. Actualiza y revisa la lista; no vuelvas a enviar la operación.`, 'warning');
  } finally {
    if (epoch === model.epoch) {
      model.pending = '';
      clearPlan({ restoreFocus: false });
      render();
      if (model.authenticated) {
        if (needsReview()) ui.reviewRefreshButton.focus(); else ui.refreshButton.focus();
        await refreshDashboard({ quiet: true });
      }
    }
  }
}

function clearPolicyResult(message = '') {
  model.policyPreview = null;
  model.policyRevision = null;
  ui.policyResults.hidden = true;
  // Never hide feedback at the bottom of the long designer form.
  text(ui.policyError, '');
  ui.policyError.hidden = true;
  if (message) notice(message, 'warning');
}

function markPolicyDirty() {
  model.policyVersion += 1;
  clearPolicyResult();
}

function renderPolicyAccess() {
  const disabled = !model.authenticated || !!model.pending || !model.csrf;
  ui.policyPreviewButton.disabled = disabled;
  ui.policyExampleButton.disabled = disabled;
  ui.policyAddBlockButton.disabled = disabled || ui.policyBlocks.children.length >= 32;
  setActionButton(ui.policyPreviewButton, model.pending === 'policy-preview' ? 'Calculando…' : 'Calcular propuesta', 'calculator');
  const candidate = selectExactBatch(model.policyPreview, model.state, model.policyRevision);
  ui.policyApplyButton.hidden = !model.policyPreview;
  ui.policyApplyButton.disabled = !candidate.ready || !canWrite('add') || !!model.policyBatch;
  setActionButton(ui.policyApplyButton, candidate.ready ? 'Revisar ' + candidate.numbers.length + ' bloqueos' : 'Aplicar números exactos', 'shield');
  text(ui.policyApplyHelp, candidate.reason);
  ui.policyForm.setAttribute('aria-busy', model.pending === 'policy-preview' ? 'true' : 'false');
}

function addPolicyBlock() {
  if (ui.policyBlocks.children.length >= 32) return;
  const sequence = ++model.policyRowSequence;
  const row = make('div', 'policy-block');
  row.dataset.sequence = String(sequence);
  const field = (name, label, input) => {
    const wrapper = make('div', `policy-field policy-field-${name}`);
    input.id = `policy-${sequence}-${name}`;
    input.dataset.field = name;
    const caption = make('label', '', label);
    caption.htmlFor = input.id;
    wrapper.append(caption, input);
    return wrapper;
  };
  const kind = make('select');
  for (const [value, label] of [['exact', 'Número exacto'], ['prefix', 'Prefijo y longitud'], ['range', 'Rango numérico'], ['pattern', 'Máscara de dígitos']]) {
    const option = make('option', '', label); option.value = value; kind.append(option);
  }
  kind.value = 'exact';
  const input = (name, label, mode = 'numeric') => {
    const element = make('input'); element.type = 'text'; element.inputMode = mode;
    element.autocomplete = 'off'; element.spellcheck = false;
    return field(name, label, element);
  };
  const value = input('value', 'Número o patrón');
  const length = input('length', 'Longitud total');
  const from = input('from', 'Desde');
  const to = input('to', 'Hasta');
  const remove = make('button', 'policy-remove');
  setActionButton(remove,'Quitar condición','trash');
  remove.type = 'button'; remove.setAttribute('aria-label', `Quitar condición ${sequence}`);
  remove.addEventListener('click', () => {
    row.remove(); markPolicyDirty(); renderPolicyAccess();
    ui.policyAddBlockButton.focus();
  });
  const updateFields = () => {
    value.hidden = kind.value === 'range';
    length.hidden = kind.value !== 'prefix';
    from.hidden = to.hidden = kind.value !== 'range';
    text(value.querySelector('label'), kind.value === 'prefix' ? 'Prefijo' : kind.value === 'pattern' ? 'Máscara' : 'Número exacto');
    value.querySelector('input').inputMode = kind.value === 'pattern' ? 'text' : 'numeric';
  };
  kind.addEventListener('change', () => { updateFields(); markPolicyDirty(); });
  row.addEventListener('input', markPolicyDirty);
  row.append(field('kind', 'Tipo', kind), value, length, from, to, remove);
  updateFields();
  ui.policyBlocks.append(row);
  markPolicyDirty(); renderPolicyAccess();
}

function policyRequest() {
  const blocks = [...ui.policyBlocks.children].map((row) => {
    const get = (name) => row.querySelector(`[data-field="${name}"]`).value;
    const kind = get('kind');
    if (kind === 'range') {
      if (!DIGITS.test(get('from')) || !DIGITS.test(get('to'))) throw new Error('En cada rango, introduce dos números de 1 a 32 dígitos sin espacios.');
      return { kind, from: get('from'), to: get('to') };
    }
    const value = get('value');
    if (!value) throw new Error('Falta completar una condición. Rellénala o elimínala.');
    if (kind !== 'pattern' && !DIGITS.test(value)) throw new Error('Los números y prefijos deben contener de 1 a 32 dígitos, sin espacios ni +.');
    if (kind === 'prefix') {
      const rawLength = get('length');
      if (!/^[1-9][0-9]?$/.test(rawLength) || Number(rawLength) > 32) throw new Error('Indica una longitud total entre 1 y 32 dígitos para el prefijo.');
      return { kind, value, length: Number(rawLength) };
    }
    return { kind, value };
  });
  if (!blocks.length) throw new Error('Añade al menos una condición a la propuesta.');
  const lines = (value) => value.split(/\r?\n/).filter((line) => line !== '');
  const exceptions = lines(ui.policyExceptions.value);
  if (exceptions.some((value) => !DIGITS.test(value))) throw new Error('Escribe cada excepción como un número exacto, en una línea y sin espacios.');
  return { blocks, exceptions, samples: lines(ui.policySamples.value) };
}

function formatCount(value) {
  const digits = String(value);
  return /^[0-9]+$/.test(digits) ? digits.replace(/\B(?=(\d{3})+(?!\d))/g, '.') : '—';
}

function renderPolicyResult(data) {
  const result = data.preview;
  if (!result || !/^[0-9]+$/.test(String(result.count)) || !Array.isArray(result.referenceMasks) ||
    !result.referenceMasks.every((value) => typeof value === 'string') || !result.capacity ||
    !Array.isArray(result.samples) || !Array.isArray(result.conflicts) || !Array.isArray(result.unknownExisting) || !result.exceptions) {
    throw new Error('No se puede comprobar la propuesta recibida. Vuelve a calcularla.');
  }
  model.policyPreview = result;
  model.policyRevision = data.revision;
  text(ui.policyCoverage, formatCount(result.count));
  text(ui.policyMaskCount, formatCount(result.capacity.referenceMaskCount));
  text(ui.policySlots, `${formatCount(result.capacity.available)} / ${formatCount(result.capacity.limit)}`);
  text(ui.policyCalculatedAt, `Calculada a las ${dateLabel(data.capturedAt)} · modelo de referencia, sin cambios en el router.`);
  text(ui.policyCapacity, result.capacity.referenceMaskFits
    ? `La propuesta ocuparía ${result.capacity.referenceMaskCount} huecos de los ${result.capacity.available} disponibles.`
    : `La propuesta necesita ${result.capacity.referenceMaskCount} huecos y hay ${result.capacity.available} disponibles. Supera la capacidad actual.`);
  ui.policyCapacity.classList.toggle('is-over-capacity', !result.capacity.referenceMaskFits);
  const unmatched = Array.isArray(result.exceptions.unmatched) ? result.exceptions.unmatched.length : 0;
  text(ui.policyExceptionSummary, `${formatCount(result.exceptions.uniqueCount)} excepciones distintas; ${formatCount(result.exceptions.excludedCount)} números excluidos de la propuesta.${unmatched ? ` ${unmatched} excepciones no coincidían con su cobertura.` : ''}`);
  ui.policyCompiledList.replaceChildren(...result.referenceMasks.map((mask) => {
    const item = make('li'); item.append(make('code', '', mask)); return item;
  }));
  ui.policyCompiledEmpty.hidden = result.referenceMasks.length !== 0;
  ui.policyConflictsPanel.hidden = result.conflicts.length === 0;
  ui.policyConflicts.replaceChildren(...result.conflicts.map((conflict) => make('li', '',
    `${conflict.exception}: la regla existente ${patternDisplay(String(conflict.pattern))} también lo cubriría${conflict.certainty === 'reference' ? ' según el modelo' : ' por coincidencia exacta'}.`)));
  ui.policyUnknownPanel.hidden = result.unknownExisting.length === 0;
  ui.policyUnknown.replaceChildren(...result.unknownExisting.map((item) => make('li', '', `${patternDisplay(String(item.pattern))}: su cobertura no puede comprobarse con este modelo.`)));
  const labels = { blocked: 'Bloqueo previsto', allowed: 'Fuera del bloqueo', unknown: 'Sin determinar' };
  const policyLabels = { blocked: 'Incluido en la propuesta', exception: 'Excluido de la propuesta', unmatched: 'Fuera de la propuesta', unknown: 'Fuera del modelo' };
  ui.policySampleResults.replaceChildren(...result.samples.map((sample) => {
    const item = make('li'); const copy = make('div');
    copy.append(make('code', '', patternDisplay(String(sample.value))), make('small', '',
      sample.supported === false ? 'Formato fuera del modelo' : `${policyLabels[sample.policyDecision] || 'Resultado sin determinar'}${sample.policyDecision === 'exception' && sample.decision === 'blocked' ? ' · una regla existente lo cubriría' : ''}`));
    item.append(copy, make('span', `policy-decision is-${['blocked', 'allowed'].includes(sample.decision) ? sample.decision : 'unknown'}`, labels[sample.decision] || labels.unknown));
    return item;
  }));
  ui.policySamplesEmpty.hidden = result.samples.length !== 0;
  ui.policyExactDetails.hidden = !Array.isArray(result.exactExpansion);
  if (Array.isArray(result.exactExpansion)) {
    text(ui.policyExactSummary, `Ver los ${result.exactExpansion.length} números exactos incluidos`);
    text(ui.policyExactList, result.exactExpansion.join('\n'));
  } else text(ui.policyExactList, '');
  ui.policyResults.hidden = false;
}

async function previewPolicy(event) {
  event.preventDefault();
  if (!model.authenticated || model.pending) return;
  clearPolicyResult();
  let request;
  try { request = policyRequest(); }
  catch (error) {
    notice(error.message, 'error');
    // Point to the incomplete condition without losing the fixed-position toast.
    if (error.message === 'Falta completar una condición. Rellénala o elimínala.') {
      const firstEmpty = [...ui.policyBlocks.children].map(row => {
        const kind = row.querySelector('[data-field="kind"]')?.value;
        const names = kind === 'range' ? ['from','to'] : ['value'];
        return names.map(name => row.querySelector('[data-field="' + name + '"]'))
          .find(input => input && !input.value.trim());
      }).find(Boolean);
      firstEmpty?.focus();
    }
    return;
  }
  const epoch = model.epoch, version = model.policyVersion;
  model.pending = 'policy-preview'; render();
  try {
    const data = await api('/api/policy/preview', { method: 'POST', body: request });
    if (epoch !== model.epoch) return;
    if (version !== model.policyVersion) { clearPolicyResult('La propuesta ha cambiado. Calcula de nuevo sus resultados.'); return; }
    renderPolicyResult(data);
    notice('Propuesta calculada. No se ha cambiado el router.', 'success');
    announce('Propuesta calculada. No se ha aplicado ningún cambio al router.');
    ui.policyResultTitle.focus();
  } catch (error) {
    if (epoch !== model.epoch) return;
    notice(error.message, 'error');
  } finally {
    if (epoch === model.epoch) { model.pending = ''; render(); }
  }
}


function batchControls() {
  const batch = model.policyBatch;
  ui.policyApplyCancel.hidden = !batch || batch.started;
  ui.policyApplyConfirm.hidden = !batch || batch.started;
  ui.policyApplyStop.hidden = !batch || !batch.running;
  ui.policyApplyClose.hidden = !batch || !batch.finished;
  ui.policyApplyConfirm.disabled = !batch || batch.started || !!model.pending;
  ui.policyApplyStop.disabled = !batch || !batch.running || batch.stopRequested;
}
function openPolicyBatch() {
  const candidate = selectExactBatch(model.policyPreview, model.state, model.policyRevision);
  if (!canWrite('add') || !candidate.ready || model.policyBatch) return;
  model.policyBatch = {
    numbers: candidate.numbers.slice(), revision: model.policyRevision,
    version: model.policyVersion, epoch: model.epoch, applied: [],
    started: false, running: false, finished: false, stopRequested: false, uncertain: false,
  };
  text(ui.policyApplySummary, 'Se añadirán ' + candidate.numbers.length +
    ' números completos. Cada alta se verificará antes de enviar la siguiente.');
  text(ui.policyApplyList, candidate.numbers.join('\n'));
  text(ui.policyApplyProgress, 'Sin cambios enviados.');
  batchControls();
  ui.policyApplyDialog.showModal();
  ui.policyApplyCancel.focus();
  render();
}
function closePolicyBatch() {
  const batch = model.policyBatch;
  if (!batch || batch.running) return;
  if (ui.policyApplyDialog.open) ui.policyApplyDialog.close();
  model.policyBatch = null;
  if (batch.applied.length) notice('Se verificaron ' + batch.applied.length +
    ' altas. No se han retirado ni repetido. Comprueba la lista antes de otra tanda.',
    batch.uncertain ? 'warning' : 'success');
  render();
  void refreshDashboard({quiet: true});
  ui.refreshButton.focus();
}
async function startPolicyBatch() {
  const batch = model.policyBatch;
  if (!batch || batch.started || !canWrite('add') || batch.version !== model.policyVersion ||
      batch.revision !== model.policyRevision || batch.epoch !== model.epoch) return;
  batch.started = true;
  batch.running = true;
  model.pending = 'policy-batch';
  model.stale = true;
  stopPolling();
  batchControls();
  render();
  try {
    const result = await runExactBatch({
      api, numbers: batch.numbers, revision: batch.revision,
      epochValid: () => batch.epoch === model.epoch && model.authenticated,
      shouldStop: () => batch.stopRequested,
      onProgress: (step) => {
        if (batch.epoch !== model.epoch) return;
        const phase = step.phase === 'plan' ? 'Preparando número…' :
          step.phase === 'commit' ? 'Enviando y verificando un alta…' : 'Alta comprobada.';
        text(ui.policyApplyProgress, 'Verificados: ' + step.applied + ' de ' + step.total + '. ' + phase);
      },
      onApplied: (step) => {
        if (batch.epoch !== model.epoch) return;
        mergeOperation(step.operation);
        model.state = step.state;
        model.policyRevision = step.state.revision;
        model.stale = false;
      },
    });
    if (batch.epoch !== model.epoch) {
      if (result.pendingPlan && !model.recovery) rememberPendingIdentity(result.pendingPlan.planId, result.pendingPlan.operationId);
      return;
    }
    batch.applied = result.applied.slice();
    batch.uncertain = result.uncertain;
    if (result.lastState && validState(result.lastState)) {
      model.state = result.lastState;
      model.policyRevision = result.lastState.revision;
      model.stale = false;
    }
    if (result.uncertain) {
      model.uncertain = true;
      model.stale = true;
      if (result.pendingPlan) {
        model.submission = {planId: result.pendingPlan.planId, type: 'add',
          pattern: result.pendingPlan.pattern, ruleId: null};
        model.trackedOperation = result.pendingPlan.operationId;
      }
    }
    const verified = batch.applied.length, remaining = batch.numbers.length - verified;
    if (result.error) {
      text(ui.policyApplyProgress, 'Tanda interrumpida: ' + verified + ' de ' + batch.numbers.length +
        ' altas verificadas. ' + result.error +
        ' No habrá reintentos automáticos; las altas previas permanecen.');
    } else if (result.stopped) {
      text(ui.policyApplyProgress, 'Detenida: ' + verified + ' altas verificadas y ' + remaining +
        ' pendientes. Las reglas completadas permanecen activas.');
    } else {
      text(ui.policyApplyProgress, 'Terminada: ' + verified +
        ' altas individuales verificadas. No se han enviado máscaras ni se han borrado reglas.');
    }
  } catch (error) {
    if (batch.epoch !== model.epoch) return;
    batch.uncertain = true;
    model.uncertain = true;
    model.stale = true;
    text(ui.policyApplyProgress, 'Resultado de la tanda no comprobable. ' +
      'No se repetirán altas automáticamente. Actualiza la lista y la actividad antes de seguir.');
  } finally {
    batch.running = false;
    batch.finished = true;
    if (batch.epoch !== model.epoch) return;
    model.pending = '';
    if (batch.applied.length) clearPolicyResult('La lista cambió. Recalcula la propuesta para ver qué falta.');
    batchControls();
    render();
    announce('Tanda detenida o completada. Revisa los números efectivamente aplicados.');
  }
}

ui.policyForm.addEventListener('submit', previewPolicy);
ui.policyApplyButton.addEventListener('click', openPolicyBatch);
ui.policyApplyConfirm.addEventListener('click', startPolicyBatch);
ui.policyApplyCancel.addEventListener('click', closePolicyBatch);
ui.policyApplyClose.addEventListener('click', closePolicyBatch);
ui.policyApplyStop.addEventListener('click', () => {
  if (!model.policyBatch?.running) return;
  model.policyBatch.stopRequested = true;
  text(ui.policyApplyProgress, 'Detención solicitada. Se verificará el alta en curso antes de parar.');
  batchControls();
});
ui.policyApplyDialog.addEventListener('cancel', (event) => {
  event.preventDefault();
  if (!model.policyBatch?.running) closePolicyBatch();
});
function loadPolicyExample(){
  if(!model.authenticated||model.pending||ui.policyBlocks.children.length!==1)return;
  const row=ui.policyBlocks.firstElementChild;
  const kind=row.querySelector('[data-field="kind"]');
  const existing=[...row.querySelectorAll('input')].some(el=>el.value.trim())||
    ui.policyExceptions.value.trim()||ui.policySamples.value.trim();
  if(existing||kind.value!=='exact'){
    notice('El ejemplo solo se carga en una propuesta vacía. Conserva tus condiciones actuales.','warning');
    return;
  }
  kind.value='prefix';
  kind.dispatchEvent(new Event('change',{bubbles:true}));
  row.querySelector('[data-field="value"]').value='912';
  row.querySelector('[data-field="length"]').value='9';
  ui.policySamples.value='912345678\n934567890';
  markPolicyDirty();
  renderPolicyAccess();
  ui.policyPreviewButton.focus();
  notice('Ejemplo cargado sin modificar el router. Pulsa Calcular propuesta.','success');
}
ui.policyExampleButton.addEventListener('click',loadPolicyExample);
ui.policyAddBlockButton.addEventListener('click', () => { if (!model.pending) addPolicyBlock(); });
ui.policyExceptions.addEventListener('input', markPolicyDirty);
ui.policySamples.addEventListener('input', markPolicyDirty);
addPolicyBlock();

ui.connectForm.addEventListener('submit', connect);
ui.password.addEventListener('input', () => {
  ui.connectError.hidden = true;
  ui.connectButton.disabled = !model.csrf || !!model.pending || !ui.password.value || model.disconnectFailed || model.validatingSession;
});
ui.disconnectButton.addEventListener('click', disconnect);
ui.refreshButton.addEventListener('click', () => refreshDashboard());
ui.historyLoadButton.addEventListener('click', loadCallHistory);
function showAutodialMessage(message){
  ui.autodialMessage.hidden=!message;
  text(ui.autodialMessage,message||'');
}
async function readAutodial(){
  if(!model.authenticated||model.pending)return;
  const epoch=model.epoch;
  model.pending='autodial-read';render();
  try{
    const result=await api('/api/phones/autodial');
    if(epoch!==model.epoch)return;
    if(typeof result.enabled!=='boolean'||typeof result.number!=='string'||
      !Number.isInteger(result.seconds)||typeof result.revision!=='string')
      throw new ApiError('Respuesta de automarcado no válida.','AUTODIAL_SCHEMA');
    model.autodial=result;
    ui.autodialNumber.value=result.number;
    ui.autodialTimeout.value=String(result.seconds);
    showAutodialMessage(result.reviewRequired?
      'Existe un intento sin verificación concluyente. Consulta el estado nativo antes de volver a guardar.':'');
  }catch(e){if(epoch===model.epoch)showAutodialMessage('No se pudo leer el automarcado: '+e.message);}
  finally{if(epoch===model.epoch){model.pending='';render();}}
}
ui.autodialOpen.addEventListener('click',()=>{
  if(!model.authenticated||model.pending||running()||needsReview())return;
  model.autodial=null;model.autodialPlan=null;
  showAutodialMessage('');
  ui.autodialDialog.showModal();
  void readAutodial();
});
ui.autodialRefresh.addEventListener('click',()=>void readAutodial());
ui.autodialNumber.addEventListener('input',render);
ui.autodialTimeout.addEventListener('input',render);
ui.autodialClose.addEventListener('click',()=>{
  if(!model.pending)ui.autodialDialog.close();
});
ui.autodialDialog.addEventListener('cancel',event=>{
  if(model.pending)event.preventDefault();
});
ui.autodialDialog.addEventListener('close',()=>{
  model.autodial=null;model.autodialPlan=null;
  ui.autodialNumber.value='';ui.autodialTimeout.value='';
  if(model.authenticated&&ui.autodialOpen.isConnected)ui.autodialOpen.focus();
});
async function prepareAutodial(type){
  if(!model.authenticated||model.pending||!model.autodial||
    model.autodial.reviewRequired||running())return;
  const value=type==='enable'?!model.autodial.enabled:
    type==='number'?ui.autodialNumber.value:Number(ui.autodialTimeout.value);
  const epoch=model.epoch;
  model.pending='autodial-prepare';render();
  try{
    const plan=await api('/api/phones/autodial/prepare',{method:'POST',
      body:{type,value,revision:model.autodial.revision}});
    if(epoch!==model.epoch)return;
    if(typeof plan.planId!=='string'||typeof plan.summary!=='string')
      throw new ApiError('Confirmación incompleta.','INVALID_RESPONSE');
    model.autodialPlan=plan;
    text(ui.autodialConfirmSummary,plan.summary+
      (type==='number'?' Número propuesto: '+value:
       type==='timeout'?' Espera propuesta: '+value+' segundos.':''));
    ui.autodialConfirmDialog.showModal();
    ui.autodialConfirmCancel.focus();
  }catch(error){if(epoch===model.epoch)showAutodialMessage('No se preparó el cambio: '+error.message);}
  finally{if(epoch===model.epoch){model.pending='';render();}}
}
ui.autodialToggle.addEventListener('click',()=>void prepareAutodial('enable'));
ui.autodialSaveNumber.addEventListener('click',()=>void prepareAutodial('number'));
ui.autodialSaveTimeout.addEventListener('click',()=>void prepareAutodial('timeout'));
ui.autodialConfirmCancel.addEventListener('click',()=>{
  if(model.pending!=='autodial-commit'){model.autodialPlan=null;ui.autodialConfirmDialog.close();}
});
ui.autodialConfirmDialog.addEventListener('cancel',e=>{
  if(model.pending==='autodial-commit')e.preventDefault();else model.autodialPlan=null;
});
ui.autodialConfirmApply.addEventListener('click',async()=>{
  if(model.pending||!model.autodialPlan||!model.authenticated)return;
  const plan=model.autodialPlan;
  model.autodialPlan=null;
  const epoch=model.epoch;
  model.pending='autodial-commit';render();
  try{
    const result=await api('/api/phones/autodial/commit',{method:'POST',body:{planId:plan.planId}});
    if(epoch!==model.epoch)return;
    ui.autodialConfirmDialog.close();
    showAutodialMessage(String(result.message||'El resultado no está verificado.'));
  }catch(e){
    if(epoch!==model.epoch)return;
    if(ui.autodialConfirmDialog.open)ui.autodialConfirmDialog.close();
    showAutodialMessage('Resultado incierto: '+e.message+' No repitas el envío; actualiza el estado.');
  }finally{
    if(epoch===model.epoch){
      model.pending='';render();
      if(ui.autodialDialog.open)void readAutodial();
    }
  }
});
ui.phoneRingOpen.addEventListener('click',()=>{
  if(!model.authenticated||model.pending||running()||needsReview()||model.monitorStopped)return;
  ui.phoneRingStatus.hidden=true;
  text(ui.phoneRingStatus,'');
  ui.phoneRingDialog.showModal();
  ui.phoneRingCancel.focus();
});
ui.phoneRingCancel.addEventListener('click',()=>{
  if(model.pending!=='phone-ring-test')ui.phoneRingDialog.close();
});
ui.phoneRingDialog.addEventListener('cancel',event=>{
  if(model.pending==='phone-ring-test')event.preventDefault();
});
ui.phoneRingConfirm.addEventListener('click',async()=>{
  if(!model.authenticated||model.pending||running()||needsReview())return;
  const epoch=model.epoch;
  model.pending='phone-ring-test';
  ui.phoneRingStatus.hidden=false;
  text(ui.phoneRingStatus,'Enviando una única solicitud al Livebox…');
  render();
  try{
    const result=await api('/api/phones/ring-test',{method:'POST',body:{}});
    if(epoch!==model.epoch)return;
    text(ui.phoneRingStatus,String(result.message||'No se ha podido verificar el timbrado físico.'));
    notice(result.requested?'Solicitud de prueba enviada. Comprueba los teléfonos.':
      'No se confirmó la solicitud. No la repitas automáticamente.',
      result.requested?'success':'warning');
  }catch(error){
    if(epoch!==model.epoch)return;
    text(ui.phoneRingStatus,'No se pudo confirmar la prueba: '+error.message+
      ' Comprueba si sonaron los teléfonos antes de solicitar otra.');
    notice('La prueba no quedó confirmada. No se repetirá automáticamente.','warning');
  }finally{
    if(epoch===model.epoch){
      model.pending='';
      render();
      if(ui.phoneRingDialog.open)ui.phoneRingCancel.focus();
    }
  }
});
ui.reviewRefreshButton.addEventListener('click', () => model.clearReview?reconcileClear():refreshDashboard());
ui.numberInput.addEventListener('input', () => { model.inputTouched = true; renderNumber(); });
 ui.addMode.addEventListener('change', () => {
   ui.numberInput.value = '';
   model.inputTouched = false;
   renderNumber();
   if (!ui.numberInput.disabled) ui.numberInput.focus();
 });
ui.addForm.addEventListener('submit', (event) => {
  event.preventDefault();
  model.inputTouched = true;
  renderNumber();
  if (!canWrite('add') || numberError()) { if (!ui.numberInput.disabled) ui.numberInput.focus(); return; }
  preparePlan({ type: 'add', pattern: proposedAddPattern() }, ui.addButton);
});
ui.cancelPlanButton.addEventListener('click', () => { if (model.pending !== 'commit') clearPlan(); });
ui.confirmDialog.addEventListener('cancel', (event) => {
  event.preventDefault();
  if (model.pending !== 'commit') clearPlan();
});
ui.commitButton.addEventListener('click', commitPlan);
async function checkVisibleSession() {
  if (document.hidden) return;
  if (model.sessionDeadline && Date.now() >= model.sessionDeadline && model.authenticated) {
    invalidateSession('expired', 'La sesión ha caducado. Conecta de nuevo para continuar.'); return;
  }
  if (model.disconnectFailed) { await disconnect(); return; }
  const epoch = model.epoch, wasAuthenticated = model.authenticated;
  model.validatingSession = wasAuthenticated; render();
  try {
    const session = await api('/api/session');
    if (epoch !== model.epoch) return;
    if (wasAuthenticated && !session.authenticated) {
      invalidateSession('expired', 'La sesión ha terminado en el gestor. Conecta de nuevo para continuar.'); return;
    }
    if (wasAuthenticated) acceptSession(session);
    else { model.csrf = session.csrf; updateSessionDeadline(session.expiresAt, session.serverTime); }
    model.validatingSession = false; render(); if(!model.legacy)schedulePoll();
  } catch (error) {
    if (epoch === model.epoch) invalidateSession('connection', 'No se puede comprobar la sesión. Los datos se han retirado hasta recuperar la conexión.', {recover: false});
  } finally { if (epoch === model.epoch) { model.validatingSession = false; render(); } }
}
window.addEventListener('pagehide', () => { clearSessionView(); model.pending = ''; model.csrf = ''; });
window.addEventListener('pageshow', event => { if (event.persisted) void refreshDashboard({quiet: true}); });
document.addEventListener('visibilitychange', () => {
  if (document.hidden) { ui.password.value = ''; stopPolling(); }
  else void checkVisibleSession();
});
window.addEventListener('offline', () => invalidateSession('offline', 'La conexión se ha interrumpido. Los datos se han retirado de la pantalla.', {recover: false}));
window.addEventListener('online', () => { void checkVisibleSession(); });


let busySince=0,busyTimer=null;
const pendingLabels={boot:'Preparando el gestor',refresh:'Actualizando el estado',connect:'Conectando con el Livebox',disconnect:'Cerrando la sesión',
  'call-history':'Cargando las llamadas','phone-ring-test':'Solicitando prueba de teléfonos','history-clear-prepare':'Preparando el vaciado','history-clear':'Vaciando y verificando el historial', 'plan-add':'Preparando el bloqueo','plan-delete':'Preparando la retirada',commit:'Enviando y verificando el cambio',
  'policy-preview':'Calculando la propuesta','policy-batch':'Aplicando y verificando la tanda','settings-load':'Cargando la configuración','settings-save':'Guardando la dirección IP','settings-detect':'Detectando la puerta de enlace',
  'dns-read':'Consultando DNS del Livebox','dns-prepare':'Verificando formulario DNS','dns-commit':'Aplicando y verificando DNS'};
function renderBusy(){
  const active=!!model.pending || (model.authenticated && !model.monitorStopped && running());
  // Synchronous with the action; no one-second delay or network-dependent timer.
  document.documentElement.classList.toggle('is-busy',active);
  ui.busyBanner.hidden=!active||!bootstrapResolved;
  ui.dashboard.setAttribute('aria-busy',active?'true':'false');
  if(!active){clearInterval(busyTimer);busyTimer=null;busySince=0;}
  else if(!busySince){busySince=Date.now();busyTimer=setInterval(updateBusyTime,1000);}
  const operation=model.operations.find(item=>statusOf(item)==='running');
  const phaseLabels={preparing:'Preparando el cambio en el router',dispatching:'Enviando el cambio al router',verifying:'Cambio enviado: verificando el resultado'};
  const label=(operation && phaseLabels[operation.phase])||pendingLabels[model.pending]||(running()?'Comprobando el resultado en el router':'Operación en curso');
  text(ui.busyTitle,label);
  for(const note of document.querySelectorAll('[data-busy-note]')){note.hidden=!active;text(note,label+'… No repitas la operación.');}
  updateBusyTime();
}
function updateBusyTime(){
  if(!busySince)return;
  const seconds=Math.floor((Date.now()-busySince)/1000);
  text(ui.busyElapsed,seconds+' s');
  const verifying = !!model.recovery || model.pending === 'commit' || model.pending === 'policy-batch' || running();
  const operation=model.operations.find(item=>statusOf(item)==='running');
  const phaseDetail=operation?.phase==='preparing'?'El gestor ha reservado la operación y está comprobando el estado antes del envío.':
    operation?.phase==='dispatching'?'Se está enviando un único cambio. Espera a que el gestor compruebe su resultado.':
    operation?.phase==='verifying'?'El cambio se ha enviado. El gestor está comprobando la lista resultante; no repitas el envío.':'';
  text(ui.busyDetail, seconds * 1000 >= REQUEST_BUDGETS.slowMs
    ? (phaseDetail || (verifying ? 'Operación enviada o reservada, pendiente de verificación. No repitas el envío.' : 'La consulta sigue en curso dentro del plazo previsto.')) + ' El router está tardando más de lo habitual.'
    : phaseDetail || (verifying ? 'Esperando la verificación del gestor; no se repetirá el envío.' : 'Consulta en curso. Esperando la respuesta del router o del gestor…'));
  if (!model.monitorStopped && model.monitorDeadline && Date.now() >= model.monitorDeadline && running()) stopAutomaticMonitoring('La comprobación automática ha alcanzado su plazo. El resultado queda pendiente de revisión manual; no se reenviará la operación.');
}
function themePreference(){return document.documentElement.dataset.themePreference||'system';}
function applyTheme(value,persist=true){
  const pref=['light','dark','system'].includes(value)?value:'system';
  const effective=pref==='system'?(matchMedia('(prefers-color-scheme: dark)').matches?'dark':'light'):pref;
  document.documentElement.dataset.theme=effective;document.documentElement.dataset.themePreference=pref;
  if(persist)try{localStorage.setItem('rearouter_theme',pref);}catch{}
  ui.themeSelect.value=pref;
  setActionButton(ui.themeToggle,effective==='dark'?'Activar modo claro':'Activar modo oscuro',effective==='dark'?'sun':'moon',{iconOnly:true});
}
function renderSettingsAccess(){
  ui.settingsOpen.disabled=!model.csrf||!!model.pending||running();
  const editable=model.settingsCanChange&&!model.authenticated&&!model.pending&&!running();
  ui.routerIpInput.disabled=!editable;ui.settingsSave.disabled=!editable;ui.routerDetect.disabled=!editable;
  ui.settingsClose.disabled=!!model.pending;
  text(ui.settingsHint,model.authenticated?'Desconecta la sesión del router para cambiar la IP. El aspecto puede cambiarse en cualquier momento.':'IPv4 privada, sin URL ni puerto. Se guarda solo en este gestor; no modifica el router.');
}
async function openSettings(){
  if(!model.csrf||model.pending||running())return;
  const epoch=model.epoch;
  model.pending='settings-load';ui.settingsError.hidden=true;text(ui.detectResult,'');
  ui.settingsDialog.showModal();render();
  try{const config=await api('/api/settings');if(epoch!==model.epoch)return;model.routerIp=config.routerIp;model.settingsCanChange=config.canChange===true;ui.routerIpInput.value=config.routerIp;}
  catch(e){if(epoch!==model.epoch)return;text(ui.settingsError,e.message);ui.settingsError.hidden=false;}
  finally{if(epoch===model.epoch){model.pending='';render();if(!ui.routerIpInput.disabled)ui.routerIpInput.focus();}}
}
async function saveSettings(event){
  event.preventDefault();if(model.pending||model.authenticated||!model.settingsCanChange)return;
  const epoch=model.epoch;
  model.pending='settings-save';ui.settingsError.hidden=true;render();
  try{
    const saved=await api('/api/settings',{method:'POST',body:{routerIp:ui.routerIpInput.value.trim()}});
    if(epoch!==model.epoch)return;
    // Never close the dialog when persistence fails or returns an invalid result.
    if(typeof saved?.routerIp!=='string'||!/^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/.test(saved.routerIp))
      throw new ApiError('No se ha podido verificar la IP guardada. Revisa la configuración.');
    if(saved.routerIp!==model.routerIp)ui.password.value=''; // Don't carry old-router credentials to the new IP.
    model.routerIp=saved.routerIp;
    ui.routerIpInput.value=saved.routerIp;
    if(ui.settingsDialog.open)ui.settingsDialog.close();
    notice('IP guardada. La próxima conexión utilizará '+saved.routerIp+'.','success');
  }catch(e){
    if(epoch!==model.epoch)return;
    text(ui.settingsError,e.message);ui.settingsError.hidden=false;
  }finally{
    if(epoch===model.epoch){model.pending='';render();}
  }
}
async function detectRouter(){
  if(model.pending||model.authenticated||!model.settingsCanChange)return;
  const epoch=model.epoch;
  model.pending='settings-detect';ui.settingsError.hidden=true;render();
  try{const detected=await api('/api/settings/detect',{method:'POST',body:{}});
    if(epoch!==model.epoch)return;
    if(!detected.routerIp)throw new ApiError('No se ha encontrado una puerta de enlace privada. Introduce la IP manualmente.');
    ui.routerIpInput.value=detected.routerIp;
    text(ui.detectResult,'Puerta de enlace candidata: '+detected.routerIp+(detected.candidates.length>1?' · Hay '+detected.candidates.length+' puertas de enlace disponibles.':'')+' No se ha guardado ni verificado que sea un Livebox. Comprueba la dirección y pulsa Guardar IP.');
  }catch(e){if(epoch!==model.epoch)return;text(ui.settingsError,e.message);ui.settingsError.hidden=false;}
  finally{if(epoch===model.epoch){model.pending='';render();}}
}
for(const id of ['historySearch','historyType','historyPeriod','historySort','historyFrom','historyTo']){
  ui[id].addEventListener(id==='historySearch'?'input':'change',()=>{model.historyPage=0;renderCallHistory();});
}
ui.historyGroup.addEventListener('change',()=>{model.historyPage=0;renderCallHistory();});
ui.historyPrevious.addEventListener('click',()=>{if(model.historyPage>0){model.historyPage--;renderCallHistory();}});
ui.historyNext.addEventListener('click',()=>{model.historyPage++;renderCallHistory();});
ui.historyReset.addEventListener('click',()=>{resetHistoryFilters();renderCallHistory();});
ui.callAlertToggle.addEventListener('click',()=>void toggleCallNotifications());
ui.callAlertTest.addEventListener('click',()=>void testCallNotification());
ui.historyClearButton.addEventListener('click',openClearHistory);
ui.clearHistoryConfirm.addEventListener('click',confirmClearHistory);
ui.clearHistoryCancel.addEventListener('click',cancelClearHistory);
ui.clearHistoryDialog.addEventListener('cancel',event=>{event.preventDefault();cancelClearHistory();});
ui.settingsOpen.addEventListener('click',openSettings);
ui.connectionTargetIp.addEventListener('click',openSettings);
ui.settingsForm.addEventListener('submit',saveSettings);
ui.routerDetect.addEventListener('click',detectRouter);
ui.settingsClose.addEventListener('click',()=>{if(!model.pending)ui.settingsDialog.close();});
ui.settingsDialog.addEventListener('cancel',e=>{if(model.pending)e.preventDefault();});
ui.themeSelect.addEventListener('change',()=>applyTheme(ui.themeSelect.value));
ui.themeToggle.addEventListener('click',()=>applyTheme(document.documentElement.dataset.theme==='dark'?'light':'dark'));
matchMedia('(prefers-color-scheme: dark)').addEventListener('change',()=>{if(themePreference()==='system')applyTheme('system',false);});
applyTheme(themePreference(),false);

render();
refreshDashboard({ quiet: true });

import http from 'node:http';
import fs from 'node:fs/promises';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {randomBytes, randomUUID, createHash, timingSafeEqual} from 'node:crypto';
import {
  validateState, stateHash, validateWritablePattern, isFixedLengthNativePrefix, validateExistingPattern, validateRuleId,
  assertAddPreconditions, assertDeletePreconditions, validateAddDelta, validateDeleteDelta,
} from './core.mjs';
import {previewPolicy} from './policy-core.mjs';
import {validateAutodialUpdate,autoDialChanges,publicAutodial} from './autodial-core.mjs';
import {validateCallHistory,callHistoryRevision,callMarks,classifyClearEvidence,CLEAR_RESOLUTIONS} from './call-history.mjs';
import {createRouterSettings, detectRouterGateway, validateRouterIp} from './router-settings.mjs';
import {REQUEST_BUDGETS} from './public/request-budget.mjs';
import {APP_INFO} from './public/app-info.mjs';
import {mergeLegacyReadback,legacyRefreshFailed} from './public/legacy-readback.mjs';
import {serveStaticResource} from './static-resources.mjs';
import {createHttpTransport} from './http-transport.mjs';
import {createReadRoutes} from './read-routes.mjs';
import {COMPAT_PROFILE} from './compatibility.mjs';
import {lookupPublicConnection,createPublicNetworkCache} from './public-connection.mjs';
import {readLocalRouterHostname,projectRouterDeviceInfo} from './router-device-info.mjs';
import {createDnsWorkflow} from './dns-workflow.mjs';
import {probeDnsRelay} from './dns-relay-probe.mjs';
import {ensurePrivateDataDir} from './private-storage.mjs';

const publicDir = fileURLToPath(new URL('./public/', import.meta.url));
const cookieName = 'rearouter_session';
const uuid = /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/;
const sha = value => createHash('sha256').update(value).digest('hex');
const now = () => new Date().toISOString();
const messages = {
  BAD_REQUEST: 'La solicitud no tiene el formato esperado.',
  INVALID_ROUTER_IP: 'Introduce una IPv4 privada válida (192.168.x.x, 10.x.x.x o 172.16–31.x.x), sin URL ni puerto.',
  SETTINGS_INVALID: 'La configuración local no se puede validar.',
  SETTINGS_CONNECTED: 'Desconecta la sesión del router antes de cambiar su dirección IP.',
  GATEWAY_UNAVAILABLE: 'No se pudo identificar una puerta de enlace IPv4 privada. Introduce la IP manualmente.',
  SETTINGS_UNSUPPORTED: 'Este controlador no permite cambiar la dirección del router.',
  FORBIDDEN: 'La solicitud no pertenece a esta sesión local.',
  NOT_AUTHENTICATED: 'Conecta con el router antes de continuar.',
  SESSION_IN_USE: 'Otra sesión local tiene la conexión activa.',
  BUSY: 'Hay una consulta u operación en curso. Espera a que termine.',
  REVIEW_REQUIRED: 'Hay un intento pendiente de revisión. Solo se permiten lecturas.',
  PLAN_EXPIRED: 'La confirmación ha caducado. Prepara de nuevo el cambio.',
  PLAN_NOT_FOUND: 'Esta confirmación no pertenece a la sesión actual.',
  STALE_PLAN: 'El estado del router ha cambiado. No se ha enviado el cambio.',
  AUTH_FAILED: 'No se ha podido autenticar con el router.',
  LEGACY_PROFILE_UNKNOWN: 'Esta interfaz Livebox no tiene un perfil de acceso identificado. No se ha enviado ninguna contraseña.',
  LEGACY_PROFILE_UNAVAILABLE: 'No se pudo identificar la interfaz del router. Comprueba la IP y el acceso desde el navegador.',
  LEGACY_LOGIN_FORM_UNKNOWN: 'El formulario del Livebox Fibra no coincide con el procedimiento antiguo conocido. No se ha enviado ninguna contraseña.',
  LEGACY_LOGIN_UNVERIFIED: 'El Livebox Fibra no ha acreditado la autenticación. No se repetirán intentos automáticamente.',
  LEGACY_READBACK_NOT_AUTHENTICATED: 'El navegador pudo consultar el estado del Livebox Fibra, pero este no confirmó una sesión administrativa. No se repetirá el inicio de sesión automáticamente.',
  LEGACY_POST_NOT_ALLOWED: 'El formulario intentó enviar una operación no prevista por el contrato del firmware antiguo. RuxBox+ la bloqueó.',
  LEGACY_POST_NOT_DISPATCHED: 'El navegador no llegó a preparar el único envío de autenticación permitido.',
  LEGACY_POST_NO_HTTP_RESPONSE: 'Se intentó enviar la autenticación, pero no se obtuvo respuesta HTTP acreditada.',
  LEGACY_POST_HTTP_4XX: 'El router respondió con un error HTTP de cliente a la autenticación. Esto no demuestra por sí solo que la contraseña sea incorrecta.',
  LEGACY_POST_HTTP_5XX: 'El router respondió con un error HTTP de servidor al autenticar.',
  LEGACY_POST_HTTP_UNEXPECTED: 'El inicio de sesión devolvió un estado HTTP no previsto, sin acreditar autenticación.',
  LEGACY_READBACK_UNAVAILABLE: 'La respuesta de estado del Livebox Fibra no pudo verificarse desde su propio marco web. No se repetirá el inicio de sesión automáticamente.',
  LEGACY_READ_ONLY: 'Este modelo está en modo diagnóstico de solo lectura: bloqueos, llamadas y ajustes aún no están acreditados.',
  LEGACY_PHONE_SCHEMA: 'El firmware antiguo devuelve un formato de telefonía desconocido; se mantiene solo la identificación del equipo.',
  AUTH_USER: 'La cuenta de administración no coincide con la prevista.',
  CREDENTIAL_REQUIRED: 'Introduce una contraseña de administración válida.',
  PATTERN_ALREADY_PRESENT: 'Este número ya está en la lista.',
  INCOMING_CAPACITY: 'La lista de llamadas entrantes está llena.',
  PROFILES_ENABLED: 'Hay perfiles activos. Esta configuración requiere revisión.',
  DELETE_ID_NOT_FOUND: 'La regla seleccionada ya no está presente.',
  DELETE_PATTERN_MISMATCH: 'El ID seleccionado ya no corresponde a ese número.',
  INVALID_EXACT_PATTERN: 'Introduce un número exacto de 1 a 32 dígitos, o un patrón de 9 posiciones con 3–8 dígitos y x minúsculas al final.',
  PREFIX_OVERLAP: 'El prefijo coincide con una regla existente. Revísala antes de añadir otra.',
  PREFIX_EXISTING_PATTERN_UNVERIFIED: 'Existe una regla avanzada cuyo alcance no podemos determinar. No se añadirá este prefijo.',
  INVALID_EXISTING_PATTERN: 'La regla existente debe conservar su texto completo y no superar 4096 caracteres.',
  INVALID_RULE_ID: 'El identificador de la regla no es válido.',
  INVALID_POLICY: 'La política de previsualización no tiene el formato esperado.',
  INVALID_BLOCK: 'Uno de los bloques no tiene un formato admitido por el previsualizador.',
  INVALID_EXCEPTION: 'Las excepciones deben ser números literales de 1 a 32 dígitos.',
  POLICY_COMPLEXITY_LIMIT: 'La política supera el límite de cálculo de esta previsualización.',
  INVALID_CURRENT_STATE: 'El estado actual no permite completar esta previsualización.',
  LOCAL_STORAGE: 'No se ha podido asegurar el registro local de la operación.',
  PRIVATE_STORAGE_UNSAFE: 'La carpeta de datos no tiene permisos privados verificables. No se ha iniciado el gestor.',
  BROWSER_UNAVAILABLE: 'Necesitas Chrome, Brave o Edge instalado, o definir REAROUTER_CHROME con una ruta absoluta.',
  LOCAL_LOCKED: 'El directorio de datos tiene un bloqueo de otra instancia. No se elimina automáticamente.',
  INVALID_SNAPSHOT: 'La lectura del router no tiene el esquema esperado.',
  ROUTER_UNAVAILABLE: 'No se ha podido verificar la comunicación con el router.',
  ROUTER_TIMEOUT: 'El router ha superado el tiempo previsto. La consulta se cancela de forma segura; no se repite ningún envío.',
  REQUEST_CANCELLED: 'La consulta local se ha cancelado. No se ha enviado una nueva operación.',
  READ_UNAVAILABLE: 'No se ha podido obtener una lectura verificable del router.',
  CALL_LOG_SCHEMA: 'El historial de llamadas ha cambiado de formato y no puede mostrarse con seguridad.',
  CALL_LOG_TOO_LARGE: 'El historial supera el presupuesto seguro de 128 KiB. Esta lectura se ha rechazado sin alterar los registros del router.',
  CALL_LOG_EMPTY: 'El Livebox no ha devuelto llamadas. No se ha enviado ningún borrado.',
  CLEAR_UNAVAILABLE: 'El controlador del router no acredita el borrado seguro del historial.',
  CLEAR_REVIEW: 'Un borrado anterior necesita revisión. No se permite otro envío.',
  CLEAR_CONFIRMATION: 'Confirma expresamente el borrado total del historial de llamadas.',
  CALL_LOG_CHANGED: 'El historial ha cambiado desde que se preparó el borrado. Prepáralo de nuevo para revisar el total actual.',
  CLEAR_ATTEMPT_UNKNOWN: 'No existe ese intento de vaciado en este gestor.',
  CLEAR_ROUTER_MISMATCH: 'El intento de vaciado pertenece a otro router o a otro perfil. No se ha comprobado nada.',
  CLEAR_SETTLING: 'El envío es demasiado reciente. Espera un minuto antes de comprobar su resultado.',
  LEGACY_CLEAR_UNVERIFIED: 'La página del Livebox Fibra no presenta la acción nativa de vaciado reconocida. No se ha enviado nada.',
  LEGACY_APPLY_INVALID: 'La operación no corresponde a un cambio nativo permitido. No se ha enviado nada.',
  LEGACY_APPLY_FORM: 'El formulario nativo del Livebox Fibra no coincide con el formato acreditado. No se ha enviado nada.',
  PHONE_SCHEMA: 'La configuración de telefonía requiere revisión.',
  COMPAT_READ_ONLY: 'Esta acción no está acreditada para la estructura actual del firmware. La consulta sigue disponible.',
  COMPAT_REQUIRED_FIELD_MISSING: 'El router ha cambiado campos esenciales de bloqueo. No se pueden interpretar con seguridad.',
  COMPAT_SCHEMA: 'La respuesta del router no se puede interpretar con seguridad.',
  COMPAT_LIMITED: 'Se han detectado diferencias de compatibilidad. Las funciones afectadas quedan en solo lectura; las operaciones compatibles siguen disponibles.',
  ISP_LOOKUP_UNAVAILABLE: 'La información pública del operador no está disponible. Puedes volver a consultarla sin modificar el router.',
  DEVICE_INFO_UNAVAILABLE: 'No se ha podido leer el modelo o el firmware del Livebox. Puedes reintentar sin modificarlo.',
  DEVICE_INFO_SCHEMA: 'El firmware ha cambiado el formato de su información del sistema. No se han realizado cambios.',
  DNS_INVALID: 'Introduce dos direcciones IPv4 DNS distintas y válidas.',
  DNS_SCHEMA: 'El Livebox ha devuelto un formato DNS desconocido. No se ha realizado ningún cambio.',
  DNS_PAGE_UNAVAILABLE: 'El Livebox no ha abierto la página DNS autenticada. No se ha enviado ningún cambio.',
  DNS_FUNCTIONS_MISSING: 'La página DNS no ha cargado sus funciones nativas. No se ha enviado ningún cambio.',
  DNS_COMMAND_MISSING: 'Este firmware no declara DNS_CONF en la página DNS. No se ha enviado ningún cambio.',
  DNS_FIELD_MISSING: 'Este firmware no expone el campo wan_dns0. No se ha enviado ningún cambio.',
  DNS_UNAVAILABLE: 'Este firmware no acredita el formulario DNS nativo. No se enviará ninguna modificación.',
  DNS_FORM_MISMATCH: 'El formulario DNS del Livebox contiene campos no acreditados. No se enviará el cambio.',
  DNS_UNCHANGED: 'Las DNS propuestas ya están configuradas en el router.',
  DNS_REVIEW_REQUIRED: 'Existe un intento DNS incierto. Consulta su resultado antes de efectuar otro cambio.',
  DNS_RELAY_UNAVAILABLE: 'No se pudo identificar de forma segura el DNS que utiliza el proxy del router. No se ha enviado ningún cambio.',
  DNS_RECONCILE_INTEGRITY: 'El recibo o la evidencia de conciliación ha cambiado. Se mantiene bloqueado cualquier nuevo envío DNS.',
  DNS_RECONCILE_NOT_ELIGIBLE: 'No existe exactamente un intento DNS verificable que pueda conciliarse sin riesgo.',
  DNS_RECONCILE_READ_FAILED: 'No se han obtenido dos lecturas DNS independientes y válidas. No se ha cambiado la configuración.',
  DNS_RECONCILE_CONFIRMATION: 'Debes confirmar expresamente el cierre de revisión independiente de un nuevo envío DNS.',
  DNS_RECONCILE_EXPIRED: 'La comprobación anterior ha caducado o no coincide con el recibo. Verifica de nuevo, sin aplicar cambios.',
  DNS_RECONCILE_CHANGED: 'El estado DNS ha cambiado respecto a la revisión original. No se ha cerrado la incidencia ni enviado una configuración.',
  DNS_CONFIRMATION: 'Confirma expresamente las dos direcciones DNS antes de aplicar.',
  ROUTER_SCHEMA_CHANGED: 'El esquema del router ha cambiado.',
  BASELINE_INTEGRITY: 'La referencia local del router no supera la comprobación de integridad.',
  FORM_MISMATCH: 'El formulario nativo no coincide con el esperado.',
  FORM_CONFIGURATION_FIELDS: 'El formulario contiene campos ajenos a la acción permitida.',
  ATTEMPT_CONSUMED: 'El intento ya está reservado y no puede repetirse.',
  AUTODIAL_SCHEMA: 'El Livebox devuelve una configuración de automarcado desconocida o desigual entre las dos líneas internas. No se ha cambiado nada.',
  AUTODIAL_INVALID: 'Introduce un número válido (máximo 32 caracteres) o una espera de 1 a 10 segundos.',
  AUTODIAL_UNCHANGED: 'Este ajuste ya tiene el valor indicado.',
  AUTODIAL_STALE: 'El automarcado ha cambiado respecto a la lectura anterior. Vuelve a consultar antes de guardar.',
  AUTODIAL_FORM_MISMATCH: 'Los campos del formulario nativo no coinciden con el formato acreditado. No se enviará ningún cambio.',
  AUTODIAL_REVIEW: 'Una operación anterior necesita verificación. Actualiza el estado, sin repetir el envío.',
  AUTODIAL_UNAVAILABLE: 'El controlador no ofrece gestión verificable de automarcado.',

  RING_TEST_UNAVAILABLE: 'El firmware no acredita la función de prueba de teléfonos. No se ha enviado la prueba.',
  NATIVE_RING_UNAVAILABLE: 'El Livebox no declara la acción nativa esperada para hacer sonar los teléfonos.',
  RING_TEST_COOLDOWN: 'Ya se solicitó una prueba hace poco. Espera antes de iniciarla de nuevo.',
  BODY_TOO_LARGE: 'La solicitud supera el tamaño permitido.',
  NOT_FOUND: 'Recurso no disponible.',
  METHOD_NOT_ALLOWED: 'Método no permitido.',
  STOPPING: 'El gestor se está cerrando.',
};
function fault(code, status = 400) {
  return Object.assign(new Error(code), {code, status});
}
function safeCode(error) { return Object.hasOwn(messages, error?.code) ? error.code : 'ROUTER_UNAVAILABLE'; }
function equalSecret(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string' || !/^[A-Za-z0-9_-]+$/.test(a) || !/^[A-Za-z0-9_-]+$/.test(b)) return false;
  const left = Buffer.from(a), right = Buffer.from(b);
  return left.length === right.length && timingSafeEqual(left, right);
}
function objectBody(value, required, optional = []) {
  if (!value || typeof value !== 'object' || Array.isArray(value) ||
      Object.keys(value).some(key => !required.includes(key) && !optional.includes(key)) ||
      required.some(key => !Object.hasOwn(value, key))) throw fault('BAD_REQUEST');
  return value;
}
function validateCompatibility(value,fields) {
  if(value==null){
    if(fields!==78)throw Error('COMPAT_UNDECLARED_PHONE_DRIFT');
    // Strict offline fixture drivers supplied only the original known schema.
    return {profile:'legacy-strict',model:'Interfaz de referencia',firmware:null,
      status:'compatible',features:{callHistory:'on-demand',blockList:true,
        add:true,delete:true,clearHistory:true},reasons:[],safeWrites:true,
      shape:null};
  }
  if(value.profile!==COMPAT_PROFILE||!['compatible','limited'].includes(value.status)||
     typeof value.safeWrites!=='boolean'||value.firmware!==null||
     typeof value.model!=='string'||value.model.length>80||
     !value.features||value.features.blockList!==true||value.features.callHistory!=='on-demand'||
     ['add','delete','clearHistory'].some(k=>typeof value.features[k]!=='boolean')||
     !Array.isArray(value.reasons)||value.reasons.length>8||
     value.reasons.some(x=>!/^\w{3,55}$/.test(x))||
     !value.shape||!Number.isInteger(value.shape.telephoneFieldCount)||
     value.shape.telephoneFieldCount!==fields||
     !Number.isInteger(value.shape.extraBlockingFields)||
     value.shape.extraBlockingFields<0||value.shape.extraBlockingFields>64||
     !/^[a-f0-9]{64}$/.test(value.shape.blockingFingerprint)||
     (value.shape.telephoneFingerprint!==null&&
       !/^[a-f0-9]{64}$/.test(value.shape.telephoneFingerprint)))throw Error('INVALID_COMPAT');
  if((fields!==78||!value.safeWrites)&&
     (value.features.add||value.features.delete||value.features.clearHistory))throw Error('WRITE_ON_DRIFT');
  return {profile:value.profile,model:value.model,firmware:null,status:value.status,
    features:{callHistory:'on-demand',blockList:true,add:value.features.add,
      delete:value.features.delete,clearHistory:value.features.clearHistory},
    reasons:[...value.reasons],safeWrites:value.safeWrites,
    shape:{blockingFingerprint:value.shape.blockingFingerprint,
      telephoneFingerprint:value.shape.telephoneFingerprint,
      extraBlockingFields:value.shape.extraBlockingFields,
      telephoneFieldCount:fields}};
}
function snapshotOf(value) {
  try {
    const rows=validateState(value?.rows).rows;
    const count=value?.phone?.fields;
    if(!Number.isInteger(count)||count<0||count>126||
      typeof value.phone.sha256!=='string'||!/^[a-f0-9]{64}$/.test(value.phone.sha256)||
      typeof value.capturedAt!=='string'||!Number.isFinite(Date.parse(value.capturedAt)))throw Error();
    const compatibility=validateCompatibility(value.compatibility,count);
    const phone={fields:count,sha256:value.phone.sha256};
    const revision=sha(JSON.stringify([stateHash(rows),phone.sha256]));
    if(value.revision!==revision)throw Error();
    const lineNumber=value?.lineNumber??null;
    if(lineNumber!==null&&(typeof lineNumber!=='string'||!/^\+34[89][0-9]{8}$/.test(lineNumber)))throw Error();
    const snapshot={rows,phone,revision,capturedAt:value.capturedAt};
    // Private metadata stays in RAM, not in persisted operation receipts.
    Object.defineProperty(snapshot,'lineNumber',{value:lineNumber,enumerable:false});
    Object.defineProperty(snapshot,'compatibility',{value:compatibility,enumerable:false});
    return snapshot;
  }catch{throw fault('INVALID_SNAPSHOT',502);}
}

function preflight(snapshot, action) {
  return action.type === 'add'
    ? assertAddPreconditions(snapshot.rows, action.pattern)
    : assertDeletePreconditions(snapshot.rows, action.ruleId, action.pattern);
}
function inspectDelta(operation, before, after) {
  const delta = operation.type === 'add'
    ? validateAddDelta(before.rows, after.rows, operation.pattern)
    : validateDeleteDelta(before.rows, after.rows, operation.ruleId, operation.pattern);
  return {ok: delta.ok && before.phone.sha256 === after.phone.sha256,
    phoneUnchanged: before.phone.sha256 === after.phone.sha256,
    ruleId: operation.type === 'add' ? delta.added?.id ?? null : operation.ruleId,
    issueCodes: [...new Set(delta.issues.map(issue => issue.code))],
    beforeRevision: before.revision, afterRevision: after.revision};
}
const isTimestamp = value => typeof value === 'string' && Number.isFinite(Date.parse(value)) && new Date(value).toISOString() === value;
const isHash = value => typeof value === 'string' && /^[a-f0-9]{64}$/.test(value);
function validatedStoredResult(document, operation) {
  const result = document?.operation;
  if (document?.version !== 1 || !result || typeof result !== 'object' || Array.isArray(result) ||
      result.id !== operation.id || result.planId !== operation.planId || result.type !== operation.type ||
      result.pattern !== operation.pattern || result.createdAt !== operation.createdAt ||
      !['succeeded', 'failed', 'reviewRequired'].includes(result.status) ||
      result.reviewRequired !== (result.status === 'reviewRequired') ||
      !isTimestamp(result.createdAt) || !isTimestamp(result.finishedAt) || result.finishedAt < result.createdAt ||
      ![null, 0, 1].includes(result.configurationPosts) ||
      typeof result.message !== 'string' || result.message.length > 2048) throw Error('Invalid stored result');
  const ruleId = result.ruleId === null ? null : validateRuleId(result.ruleId);
  if (operation.type === 'delete' && ruleId !== operation.ruleId) throw Error('Delete identity changed');
  let verification;
  if (result.verification !== undefined) {
    const proof = result.verification;
    if (!proof || typeof proof !== 'object' || Array.isArray(proof) || !operation.checkpoint ||
        typeof proof.ok !== 'boolean' || typeof proof.phoneUnchanged !== 'boolean' ||
        !Array.isArray(proof.issueCodes) || proof.issueCodes.length > 512 ||
        proof.issueCodes.some(code => typeof code !== 'string' || !/^[A-Z_]{1,64}$/.test(code)) ||
        proof.beforeRevision !== operation.checkpoint.revision || proof.beforeRevision !== operation.beforeSnapshot.revision ||
        !isHash(proof.afterRevision)) throw Error('Invalid stored verification');
    const proofId = proof.ruleId === null ? null : validateRuleId(proof.ruleId);
    if (operation.type === 'delete' && proofId !== operation.ruleId) throw Error('Delete verification identity changed');
    if (proof.ok && (!proof.phoneUnchanged || proof.issueCodes.length !== 0 || proofId === null ||
        proof.beforeRevision === proof.afterRevision)) throw Error('Contradictory stored verification');
    verification = {ok: proof.ok, phoneUnchanged: proof.phoneUnchanged, ruleId: proofId,
      issueCodes: [...proof.issueCodes], beforeRevision: proof.beforeRevision, afterRevision: proof.afterRevision};
  }
  let response;
  if (result.response !== undefined) {
    if (!result.response || typeof result.response.transportError !== 'boolean' ||
        !(result.response.status === null || (Number.isInteger(result.response.status) && result.response.status >= 100 && result.response.status <= 599))) throw Error('Invalid stored response');
    response = {status: result.response.status, transportError: result.response.transportError};
  }
  if (result.status === 'failed' && (result.configurationPosts !== 0 || operation.checkpoint || verification || response ||
      (operation.type === 'add' && ruleId !== null))) throw Error('Invalid no-dispatch proof');
  if (result.status === 'succeeded' && (!operation.checkpoint || result.configurationPosts === 0 ||
      !verification?.ok || !verification.phoneUnchanged || ruleId === null || verification.ruleId !== ruleId)) throw Error('Invalid success proof');
  return {status: result.status, configurationPosts: result.configurationPosts, finishedAt: result.finishedAt, ruleId,
    message: result.status === 'succeeded' ? 'Cambio verificado mediante lectura independiente.'
      : result.status === 'failed' ? 'El cambio no se envió al router.' : operation.message,
    ...(verification ? {verification} : {}), ...(response ? {response} : {})};
}
async function exclusiveJson(filename, value) {
  const handle = await fs.open(filename, 'wx', 0o600);
  try { await handle.writeFile(JSON.stringify(value, null, 2) + '\n', 'utf8'); await handle.sync(); }
  finally { await handle.close(); }
}
async function atomicJson(filename, value) {
  const temporary = filename + '.' + randomUUID() + '.tmp';
  await exclusiveJson(temporary, value);
  await fs.rename(temporary, filename);
}
async function exclusiveKey(filename,key) {
  // Key bytes never appear in JSON receipts or logs; synced before reservation.
  if(!Buffer.isBuffer(key)||key.length!==32)throw Error('Invalid clear mark key');
  const handle=await fs.open(filename,'wx',0o600);
  try { await handle.writeFile(key); await handle.sync(); }
  finally { await handle.close(); }
}
async function readJson(filename) { return JSON.parse(await fs.readFile(filename, 'utf8')); }
const HEX64=/^[a-f0-9]{64}$/;
// v1: no reconciliation proof; v2: old public 64-bit marks;
// v3: keyed HMAC-SHA256 marks with the 32-byte secret in marks.key.
function clearJournalOf(saved,id){
  if(![1,2,3].includes(saved?.version)||saved.id!==id||!isTimestamp(saved.createdAt)||
     !Number.isInteger(saved.observedCount)||saved.observedCount<1)throw Error();
  if(saved.version===1)return {version:1};
  const b=saved.binding;
  if(!HEX64.test(saved.historyRevision)||!Array.isArray(saved.marks)||
     saved.marks.length!==saved.observedCount||
     saved.marks.some(m=>typeof m!=='string'||
       !(saved.version===3?HEX64:/^[a-f0-9]{16}$/).test(m))||
     (saved.version===3&&(saved.markAlgorithm!=='hmac-sha256-v3'||
       !HEX64.test(saved.keySha256)||!HEX64.test(saved.marksSha256)||
       saved.marksSha256!==sha(JSON.stringify(saved.marks))))||
     !b||!['legacy','modern'].includes(b.profile)||typeof b.routerIp!=='string'||
     !(b.family===null||(typeof b.family==='string'&&b.family.length<=64))||
     !(b.fingerprint===null||HEX64.test(b.fingerprint)))throw Error();
  return {version:saved.version,historyRevision:saved.historyRevision,marks:[...saved.marks],
    ...(saved.version===3?{keySha256:saved.keySha256,marksSha256:saved.marksSha256}:{}),
    binding:{profile:b.profile,routerIp:b.routerIp,family:b.family,fingerprint:b.fingerprint}};
}
const CLEAR_CHECK_FILE=/^reconcile-[0-9A-Za-z-]{1,80}\.json$/;
const CLEAR_CHECK_MESSAGES=Object.freeze({
  notSent:'Comprobado: no consta ningún envío y las llamadas confirmadas siguen en el router. El vaciado no se realizó.',
  notApplied:'Comprobado: las llamadas confirmadas siguen en el router. El vaciado no se aplicó.',
  cleared:'Comprobado: las llamadas confirmadas ya no están en el router y la configuración telefónica no ha cambiado. Vaciado acreditado.',
  RECORD_WITHOUT_EVIDENCE:'El registro de este intento no conserva datos suficientes para relacionarlo con el router. Se mantiene la revisión.',
  PARTIAL_MATCH:'Solo una parte de las llamadas confirmadas sigue en el router. No se puede determinar qué ocurrió; se mantiene la revisión.',
  HISTORY_GONE_WITHOUT_DISPATCH:'Las llamadas confirmadas ya no están, pero no consta el envío. Los registros no concuerdan; se mantiene la revisión.',
  DISPATCH_UNREADABLE:'Las llamadas confirmadas ya no están y el registro de envío está dañado. Se mantiene la revisión.',
  MARK_KEY_UNAVAILABLE:'La clave privada de identificación de llamadas no está disponible o está dañada. No se puede resolver el intento automáticamente.',
  MARKS_UNREADABLE:'Las marcas del historial están dañadas. Se mantiene la revisión.',
  SETTINGS_CHANGED:'Las llamadas confirmadas ya no están, pero la configuración telefónica ha cambiado. Se mantiene la revisión.'});

/** Importing this module does not create a server or invoke any router driver. */
export async function createManagerServer({driver, dataDir, host = '127.0.0.1', port = 8765,
  detectGateway = detectRouterGateway, publicConnectionLookup = lookupPublicConnection, localRouterNameLookup = readLocalRouterHostname,
  relayProbe=probeDnsRelay, sessionTtlMs = 30 * 60_000, planTtlMs = 120_000, maxBodyBytes = 8192,
  routerTimeoutMs = REQUEST_BUDGETS.routerMs + REQUEST_BUDGETS.cleanupMs, clearSettleMs = 60_000} = {}) {
  if (typeof publicConnectionLookup !== 'function' || typeof localRouterNameLookup !== 'function' ||
      typeof relayProbe!=='function' || !driver || typeof driver.read !== 'function' || typeof driver.apply !== 'function' ||
      typeof dataDir !== 'string' || !dataDir || host !== '127.0.0.1' ||
      !Number.isInteger(port) || port < 0 || port > 65535 ||
      !Number.isFinite(sessionTtlMs) || sessionTtlMs <= 0 ||
      !Number.isFinite(planTtlMs) || planTtlMs <= 0 ||
      !Number.isFinite(routerTimeoutMs) || routerTimeoutMs <= 0 ||
      !Number.isFinite(clearSettleMs) || clearSettleMs < 0 ||
      !Number.isInteger(maxBodyBytes) || maxBodyBytes < 1 || maxBodyBytes > 8192) throw fault('BAD_REQUEST');
  dataDir = path.resolve(dataDir);
  await fs.mkdir(dataDir, {recursive: true, mode: 0o700});
  const routerSettings = await createRouterSettings(dataDir);
  // Public network data is requested only by opening the details modal.
  // Cached in RAM briefly; it is never added to operation receipts or files.
  const publicNetworkInfo=createPublicNetworkCache(publicConnectionLookup);
  // One validated, bounded lookup is shared among concurrent dialog opens.
  // The cache is in-memory only and expires after 120 seconds.
  if (typeof driver.setRouterIp === 'function') driver.setRouterIp(routerSettings.get().routerIp);
  const lockPath = path.join(dataDir, 'instance.lock');
  const lock = {pid: process.pid, startedAt: now(), instanceId: randomUUID()};
  try { await exclusiveJson(lockPath, lock); }
  catch (error) { throw fault(error?.code === 'EEXIST' ? 'LOCAL_LOCKED' : 'LOCAL_STORAGE', 503); }
  const operationsDir = path.join(dataDir, 'operations');
  const operations = new Map(), plans = new Map(), sessions = new Map(), jobs = new Set(), reads = new Set();
  const clearDir = path.join(dataDir,'history-clears');
  const autodialDir=path.join(dataDir,'autodial-attempts');
  const autodialPlans=new Map();
  let autodialReview=null; // A reserved, unverified one-shot attempt

  const clearPlans = new Map(), clearAttempts = new Map();
  const clearPublic = attempt => ({id:attempt.id, status:attempt.status, createdAt:attempt.createdAt,
    finishedAt:attempt.finishedAt||null, observedCount:attempt.observedCount,
    phase:attempt.phase, message:attempt.message, configurationPosts:attempt.configurationPosts ?? null,
    resolution:attempt.resolution||null, lastCheck:attempt.lastCheck||null});
  const lastClear = () => [...clearAttempts.values()].sort((a,b)=>b.createdAt.localeCompare(a.createdAt))[0]||null;
  const clearReview = () => [...clearAttempts.values()].some(a=>a.status==='reviewRequired'||a.status==='running');
  const pendingClear = () => [...clearAttempts.values()].filter(a=>a.status==='reviewRequired')
    .sort((a,b)=>a.createdAt.localeCompare(b.createdAt))[0]||null;
  const clearPath = attempt => path.join(clearDir,attempt.id);
  const clearPersist = attempt => atomicJson(path.join(clearPath(attempt),'result.json'),
    {version:1, attempt:clearPublic(attempt)});
  // Reconciliation receipts are written once each and never rewritten; the
  // original result.json stays as it was. Exactly one valid closing receipt
  // resolves a review; unreadable or contradictory receipts keep it.
  async function clearChecksOf(attempt){
    let names=[];
    try{names=(await fs.readdir(clearPath(attempt))).filter(n=>CLEAR_CHECK_FILE.test(n))}catch{}
    const checks=[];
    for(const name of names){
      try{
        const c=await readJson(path.join(clearPath(attempt),name));
        const rule=CLEAR_RESOLUTIONS[c.outcome];
        if(c.version!==1||c.id!==attempt.id||!isTimestamp(c.checkedAt)||typeof c.message!=='string'||
           (rule?c.status!==rule.status||c.configurationPosts!==rule.configurationPosts:
             c.outcome!=='uncertain'||c.status!==null))throw Error();
        checks.push(c);
      }catch{}
    }
    if(!checks.length)return {};
    checks.sort((a,b)=>a.checkedAt.localeCompare(b.checkedAt));
    const last=checks.at(-1),closing=checks.filter(c=>c.status!==null);
    const update={lastCheck:{checkedAt:last.checkedAt,outcome:last.outcome,message:last.message}};
    if(attempt.status==='reviewRequired'&&[2,3].includes(attempt.journal?.version)&&closing.length===1){
      const c=closing[0];
      return {...update,status:c.status,phase:'complete',configurationPosts:c.configurationPosts,
        message:c.message,resolution:{outcome:c.outcome,checkedAt:c.checkedAt}};
    }
    if(closing.length>1)update.lastCheck.message='Hay comprobaciones contradictorias guardadas. Se mantiene la revisión.';
    return update;
  }
  // dispatch.json is written (exclusive, synced) before the one native POST.
  async function clearDispatchOf(attempt){
    let text;
    try{text=await fs.readFile(path.join(clearPath(attempt),'dispatch.json'),'utf8')}
    catch(error){return error?.code==='ENOENT'?'absent':'invalid'}
    try{
      const d=JSON.parse(text);
      if(![1,2].includes(d.version)||d.id!==attempt.id||!isTimestamp(d.createdAt)||
         d.observedCount!==attempt.observedCount||(d.version===2&&!HEX64.test(d.settingsRevision)))throw Error();
      return {createdAt:d.createdAt,settingsRevision:d.version===2?d.settingsRevision:null};
    }catch{return 'invalid'}
  }
  // Fail closed for missing/truncated/symlinked secrets; never fall back to v2.
  async function clearMarkKeyOf(attempt){
    const filename=path.join(clearPath(attempt),'marks.key');
    try{
      const st=await fs.lstat(filename);
      if(!st.isFile()||st.isSymbolicLink()||st.size!==32)return null;
      const key=await fs.readFile(filename);
      if(key.length!==32||!HEX64.test(attempt.journal?.keySha256??'')||
         !timingSafeEqual(Buffer.from(sha(key),'hex'),
           Buffer.from(attempt.journal.keySha256,'hex'))){
        key.fill(0);
        return null;
      }
      return key;
    }catch{return null}
  }
  let authorizedSessionId = null, activeWork = null, cached = null;
  // Volatile diagnostic only: a fixed guard name, never a token, IP or password.
  let lastLocalConnectGuard = null;
  let lastLocalConnectOriginKind = null;
  let lastLocalConnectFetchSite = null;
  let gatewayDetection = null;
  let lastRingTestAt = 0;
  let stopping = false, closed = false, boundOrigin = `http://${host}:${port}`;
  const unresolved = () => [...operations.values()].some(op => op.status === 'reviewRequired' || op.status === 'running');
  const publicOperation = op => ({
    id: op.id, planId: op.planId, type: op.type, pattern: op.pattern, ruleId: op.ruleId ?? null,
    status: op.status, reviewRequired: op.status === 'reviewRequired', createdAt: op.createdAt,
    phase: op.phase ?? (op.status === 'running' ? 'preparing' : op.status === 'reviewRequired' ? 'uncertain' : 'complete'),
    deadlineAt: new Date(Date.parse(op.createdAt) + REQUEST_BUDGETS.operationMs).toISOString(),
    finishedAt: op.finishedAt ?? null, message: op.message,
    configurationPosts: op.configurationPosts ?? null,
    ...(op.response ? {response: op.response} : {}),
    ...(op.verification ? {verification: op.verification} : {}),
  });
  const recent = () => [...operations.values()].sort((a, b) => b.createdAt.localeCompare(a.createdAt) || b.id.localeCompare(a.id));
  const directoryOf = op => path.join(operationsDir, op.id);
  const persistResult = op => atomicJson(path.join(directoryOf(op), 'result.json'), {version: 1, operation: publicOperation(op)});
  async function releaseLock() {
    try { const own = await readJson(lockPath); if (own.instanceId === lock.instanceId) await fs.unlink(lockPath); }
    catch {}
  }
  try {
    await fs.mkdir(operationsDir, {recursive: true, mode: 0o700});
    for (const entry of await fs.readdir(operationsDir, {withFileTypes: true})) {
      if (!entry.isDirectory()) continue;
      // Even a truncated or unrecognizable operation directory blocks new writes.
      let op = {id: entry.name, planId: null, type: 'unknown', pattern: '', ruleId: null,
        status: 'reviewRequired', createdAt: now(), configurationPosts: null,
        message: 'Registro local incompleto. Se necesita revisión; no se repite ningún envío.', checkpoint: null};
      try {
        if (!uuid.test(entry.name)) throw Error();
        const reservation = await readJson(path.join(operationsDir, entry.name, 'reservation.json'));
        const source = reservation.operation;
        if (reservation.version !== 1 || source.id !== entry.name || !uuid.test(source.planId) ||
            !['add', 'delete'].includes(source.type) || !isTimestamp(source.createdAt)) throw Error();
        if (source.type === 'delete') {
          validateRuleId(source.ruleId);
          validateExistingPattern(source.pattern);
        } else validateWritablePattern(source.pattern);
        const beforeSnapshot = snapshotOf(reservation.beforeSnapshot);
        preflight(beforeSnapshot, source);
        op = {...op, id: source.id, planId: source.planId, type: source.type, pattern: source.pattern,
          ruleId: source.type === 'delete' ? source.ruleId : null, createdAt: source.createdAt, beforeSnapshot};
        try {
          const checkpoint = await readJson(path.join(directoryOf(op), 'checkpoint.json'));
          const saved = snapshotOf(checkpoint.beforeSnapshot);
          if (checkpoint.version !== 1 || !isTimestamp(checkpoint.createdAt) || checkpoint.operationId !== op.id || checkpoint.planId !== op.planId ||
              saved.revision !== beforeSnapshot.revision) throw Error();
          op.checkpoint = saved;
        } catch {}
        try {
          // No terminal state is published until every field and its proof agree.
          const staged = validatedStoredResult(await readJson(path.join(directoryOf(op), 'result.json')), op);
          Object.assign(op, staged);
        } catch {}
      } catch {}
      operations.set(op.id, op);
    }
    await fs.mkdir(autodialDir,{recursive:true,mode:0o700});
    for(const dirent of await fs.readdir(autodialDir,{withFileTypes:true})){
      if(!dirent.isDirectory())continue;
      // Unknown or incomplete records fail closed, never trigger a retry.
      const folder=path.join(autodialDir,dirent.name);
      let completed=false;
      try{
        const item=await readJson(path.join(folder,'result.json'));
        completed=item?.version===1&&['verified','notApplied'].includes(item.status);
      }catch{}
      if(!completed){
        try{
          const item=await readJson(path.join(folder,'reservation.json'));
          if(item?.version===1&&item?.id===dirent.name&&
             typeof item.revision==='string'&&
             ['enable','number','timeout'].includes(item.type)){
            autodialReview=item;
          }else autodialReview={unknown:true};
        }catch{autodialReview={unknown:true}}
      }
    }
    await fs.mkdir(clearDir,{recursive:true,mode:0o700});
    for(const entry of await fs.readdir(clearDir,{withFileTypes:true})) {
      if(!entry.isDirectory()) continue;
      // Unknown or partial receipts conservatively block only further global erasures.
      let attempt={id:entry.name,status:'reviewRequired',createdAt:now(),phase:'uncertain',
        observedCount:null,configurationPosts:null,
        message:'Intento anterior sin verificación. No se repetirá automáticamente.'};
      try {
        if(!uuid.test(entry.name)) throw Error();
        const saved=await readJson(path.join(clearDir,entry.name,'reservation.json'));
        attempt={...attempt,createdAt:saved.createdAt,observedCount:saved.observedCount,
          journal:clearJournalOf(saved,entry.name)};
        try {
          const end=await readJson(path.join(clearDir,entry.name,'result.json'));
          const value=end.attempt;
          if(end.version!==1||value?.id!==entry.name||!['succeeded','failed','reviewRequired'].includes(value.status)||
             value.createdAt!==saved.createdAt||value.observedCount!==saved.observedCount||
             !isTimestamp(value.finishedAt)||typeof value.message!=='string'||
             ![0,1,null].includes(value.configurationPosts))throw Error();
          attempt={...attempt,...value};
        }catch{}
      }catch{}
      if(uuid.test(entry.name))Object.assign(attempt,await clearChecksOf(attempt));
      clearAttempts.set(attempt.id,attempt);
    }
  } catch { await releaseLock(); throw fault('LOCAL_STORAGE', 503); }

  function claimWork(kind) {
    if (stopping) throw fault('STOPPING', 503);
    if (activeWork) throw fault('BUSY', 409);
    const token = {kind}; activeWork = token;
    const release = () => { if (activeWork === token) activeWork = null; };
    release.token = token;
    return release;
  }
  // A legacy session never reaches the modern driver, and vice versa.
  function adapter(session) {
    if (!session?.legacy) return driver;
    if (!driver.legacy) throw fault('LEGACY_READ_ONLY', 403);
    return driver.legacy;
  }
  async function routerWork(kind, task, req) {
    if (req?.rearouterSession) assertCurrentSession(req.rearouterSession, req.rearouterResponse?.rearouterAuthenticated);
    const release = claimWork(kind);
    const controller = new AbortController();
    release.token.controller = controller;
    release.token.sessionId = req?.rearouterSession?.id;
    const abort = code => { if (!controller.signal.aborted) controller.abort(fault(code, code === 'NOT_AUTHENTICATED' ? 401 : code === 'ROUTER_TIMEOUT' ? 504 : 499)); };
    const cancelled = () => abort('REQUEST_CANCELLED');
    const closed = () => { if (!req?.rearouterResponse?.writableEnded) cancelled(); };
    req?.once('aborted', cancelled);
    req?.rearouterResponse?.once('close', closed);
    const timer = setTimeout(() => abort('ROUTER_TIMEOUT'), routerTimeoutMs); timer.unref?.();
    let rejectAborted;
    const interrupted = new Promise((_, reject) => { rejectAborted = () => reject(controller.signal.reason); controller.signal.addEventListener('abort', rejectAborted, {once: true}); });
    // An HTTP timeout can return promptly, but the exclusive router lock belongs
    // to the actual task, including browser cleanup. A late task never releases
    // another task's lock or publishes stale private data.
    const running = (async () => {
      try {
        controller.signal.throwIfAborted();
        const value = await task(controller.signal);
        controller.signal.throwIfAborted();
        return value;
      } catch (error) {
        if (['AUTH_FAILED', 'AUTH_USER'].includes(error?.code) && req?.rearouterSession) invalidateSession(req.rearouterSession, false);
        throw error;
      } finally {
        clearTimeout(timer);
        controller.signal.removeEventListener('abort', rejectAborted);
        req?.off('aborted', cancelled); req?.rearouterResponse?.off('close', closed);
        release();
      }
    })();
    reads.add(running); void running.then(() => reads.delete(running), () => reads.delete(running));
    return Promise.race([running, interrupted]);
  }
  async function reconcile(snapshot) {
    // Firmware drift must never certify an old write after an outage.
    if(snapshot?.compatibility?.safeWrites===false)return;
    for (const op of operations.values()) {
      if (op.status !== 'reviewRequired' || !op.checkpoint) continue;
      try {
        const verification = inspectDelta(op, op.checkpoint, snapshot);
        if (!verification.ok) continue;
        const updated = {...op, status: 'succeeded', finishedAt: now(), verification,
          ruleId: verification.ruleId,
          message: 'Efecto exacto verificado mediante una nueva lectura. No se ha repetido el envío.'};
        await persistResult(updated);
        Object.assign(op, updated);
      } catch { /* An unverified or unpersistable outcome remains blocked. */ }
    }
  }
  function stateView(snapshot) {
    const state = validateState(snapshot.rows);
    const enabledProfiles = state.profiles.filter(profile => profile.enable !== '0').length;
    const warnings = [];
    if (enabledProfiles) warnings.push(messages.PROFILES_ENABLED);
    if (unresolved()) warnings.push(messages.REVIEW_REQUIRED);
    const compatible=snapshot.compatibility;
    if(compatible.status==='limited')warnings.push(messages.COMPAT_LIMITED);
    const free=!activeWork&&!unresolved()&&enabledProfiles===0;
    const canAdd=free&&compatible.features.add;
    const canDelete=free&&compatible.features.delete;
    const canClearHistory=free&&compatible.features.clearHistory&&!clearReview();
    return {revision: snapshot.revision, capturedAt: snapshot.capturedAt,
      lineNumber: snapshot.lineNumber ?? null,
      compatibility:{profile:compatible.profile,model:compatible.model,
        firmware:compatible.firmware,status:compatible.status,
        features:{...compatible.features},reasons:[...compatible.reasons],
        shape:compatible.shape},
      canAdd,canDelete,canClearHistory,
      incoming: state.incoming.map(({id, pattern}) => {
        let deletable = false;
        try {
          validateExistingPattern(pattern);
          // Escaped controls and multibyte characters can exceed the HTTP budget
          // even when the literal pattern is within its code-unit bound.
          deletable = Buffer.byteLength(JSON.stringify({type: 'delete', pattern, ruleId: id}), 'utf8') <= maxBodyBytes;
        } catch {}
        return {id, pattern, exact: /^[0-9]{1,32}$/.test(pattern) && !/[^0-9]/.test(pattern), deletable};
      }),
      outgoingCount: state.outgoing.length, enabledProfiles,
      canWrite: canAdd||canDelete, warnings};
  }
  function invalidateSession(session, remove = true) {
    session.password = null;
    clearTimeout(session.timer);
    session.legacy = null;
    if (remove) sessions.delete(session.id);
    if (authorizedSessionId === session.id) { authorizedSessionId = null; cached = null; }
    for (const [planId, plan] of plans) if (plan.sessionId === session.id && !plan.consumed) plans.delete(planId);
    for (const [id, plan] of clearPlans) if (plan.sessionId === session.id && !plan.consumed) clearPlans.delete(id);
    // Reserved operations retain their own password only until their one attempt
    // and readback finish. Expiration must not abandon or replay that attempt.
    if (activeWork?.sessionId === session.id && activeWork.kind !== 'mutation') {
      activeWork.controller?.abort(fault('NOT_AUTHENTICATED', 401));
    }
    if (!remove) renewSession(session);
  }
  function renewSession(session) {
    session.expiresAt = Date.now() + sessionTtlMs;
    clearTimeout(session.timer);
    session.timer = setTimeout(() => {
      if (sessions.get(session.id) === session && session.expiresAt <= Date.now()) invalidateSession(session);
    }, sessionTtlMs);
    session.timer.unref?.();
  }
  function expireSessions() {
    for (const session of sessions.values()) if (session.expiresAt <= Date.now()) invalidateSession(session);
  }
  function assertCurrentSession(session, authenticated = false) {
    expireSessions();
    if (sessions.get(session?.id) !== session || (authenticated && ((!session.password && !session.legacy) || authorizedSessionId !== session.id))) throw fault('NOT_AUTHENTICATED', 401);
    return session;
  }
  function sessionFor(req) {
    expireSessions();
    const cookies = String(req.headers.cookie || '').split(';').map(value => value.trim()).filter(value => value.startsWith(cookieName + '='));
    if (cookies.length !== 1) return null;
    return sessions.get(cookies[0].slice(cookieName.length + 1)) || null;
  }
  function requireSession(req, authenticated = false, renew = true) {
    const session = sessionFor(req);
    if (!session || (authenticated && ((!session.password && !session.legacy) || authorizedSessionId !== session.id))) throw fault('NOT_AUTHENTICATED', 401);
    // Opt-in call-history monitoring must never keep a dormant admin session alive.
    if (renew) renewSession(session);
    req.rearouterSession = session;
    if (req.rearouterResponse) {
      req.rearouterResponse.rearouterSession = session;
      req.rearouterResponse.rearouterAuthenticated ||= authenticated;
    }
    return session;
  }
  function sessionView(session) {
    const authenticated = (!!session.password || !!session.legacy) && authorizedSessionId === session.id;
    return {csrf: session.csrf, authenticated,
      ...(authenticated && session.legacy ? {legacy:session.legacy} : {}),
      routerIp:routerSettings.get().routerIp,
      expiresAt: new Date(session.expiresAt).toISOString(), serverTime: now(), sessionTtlMs,
      busy: !!activeWork, lastOperation: authenticated && recent()[0] ? publicOperation(recent()[0]) : null};
  }
  const {bodyOf,json}=createHttpTransport({
    maxBodyBytes,fault,assertCurrentSession,now,messages
  });
  async function runOperation(op, password, release) {
    let enteredCallback = false, dispatchReserved = false;
    try {
      let outcome;
      try {
        outcome = await driver.apply({password, type: op.type, pattern: op.pattern,
          ruleId: op.type === 'delete' ? op.ruleId : undefined, expectedRevision: op.beforeSnapshot.revision,
          beforeDispatch: async ({beforeSnapshot} = {}) => {
            if (enteredCallback) throw fault('ATTEMPT_CONSUMED');
            enteredCallback = true;
            const before = snapshotOf(beforeSnapshot);
            if (before.revision !== op.beforeSnapshot.revision) throw fault('STALE_PLAN', 409);
            preflight(before, op);
            await exclusiveJson(path.join(directoryOf(op), 'checkpoint.json'), {
              version: 1, operationId: op.id, planId: op.planId, createdAt: now(), beforeSnapshot: before,
            });
            op.checkpoint = before;
            dispatchReserved = true;
            op.phase = 'dispatching';
            op.message = 'Envío reservado una sola vez. El resultado quedará pendiente de verificación.';
          }});
        if (!dispatchReserved || outcome?.configurationPosts !== 1) throw fault('ROUTER_UNAVAILABLE', 502);
        op.configurationPosts = 1;
        op.response = {status: Number.isInteger(outcome.response?.status) && outcome.response.status >= 100 && outcome.response.status <= 599 ? outcome.response.status : null,
          transportError: outcome.response?.transportError === true};
      } catch (error) {
        if (!dispatchReserved) {
          const finished = {...op, status: 'failed', configurationPosts: 0,
            phase: 'complete',
            message: messages[safeCode(error)] + ' No se ha enviado el cambio.', finishedAt: now()};
          await persistResult(finished);
          Object.assign(op, finished);
          return;
        }
        op.message = 'El envío tiene resultado incierto. Se comprobará mediante lectura, sin repetirlo.';
      }
      // The driver has closed the action session. This is an independent login/read.
      op.phase = 'verifying';
      op.message = 'Operación enviada; comprobando su efecto mediante una lectura independiente. No se repetirá el envío.';
      const after = snapshotOf(await driver.read(password));
      cached = authorizedSessionId ? after : null;
      const verification = inspectDelta(op, op.beforeSnapshot, after);
      const finished = {...op, verification, finishedAt: now()};
      if (verification.ok) {
        finished.phase = 'complete';
        finished.status = 'succeeded'; finished.ruleId = verification.ruleId;
        finished.message = 'Cambio exacto verificado mediante lectura independiente; telefonía conservada.';
      } else {
        finished.phase = 'uncertain';
        finished.status = 'reviewRequired';
        finished.message = 'La lectura no acredita únicamente el cambio previsto. No se repetirá el envío; revisa el estado.';
      }
      await persistResult(finished);
      Object.assign(op, finished);
    } catch {
      const uncertain = {...op, status: 'reviewRequired', finishedAt: now(),
        phase: 'uncertain',
        message: 'No se ha podido cerrar la verificación o su registro. Solo se permiten lecturas; el envío no se repite.'};
      try { await persistResult(uncertain); } catch {}
      Object.assign(op, uncertain);
    } finally { password = null; release(); }
  }

  // legacySession is set only for the old firmware: its adapter, never the
  // modern driver, sends the one POST and performs the independent readback.
  async function runHistoryClear(attempt,password,release,{source=driver,legacySession=null,expectedRevision}={}) {
    let reserved=false;
    try {
      let outcome=null;
      try {
        outcome=await source.clearCalls({password,expectedRevision,beforeDispatch:async ({beforeRevision,observedCount,settingsRevision})=>{
          // Modern: beforeRevision already covers rules and telephony settings.
          if(!legacySession)settingsRevision=beforeRevision;
          if(reserved||typeof beforeRevision!=='string'||!Number.isInteger(observedCount)||observedCount<1||
             !HEX64.test(settingsRevision??''))throw fault('BAD_REQUEST');
          // Do not send the native POST unless this checkpoint is on disk.
          await exclusiveJson(path.join(clearPath(attempt),'dispatch.json'),
            {version:2,id:attempt.id,createdAt:now(),beforeRevision,observedCount,settingsRevision});
          reserved=true;attempt.phase='dispatching';
        }});
      }catch(error){
        if(!reserved) {
          const failed={...attempt,status:'failed',phase:'complete',finishedAt:now(),
            configurationPosts:0,message:'No se envió ningún borrado. '+messages[safeCode(error)]};
          await clearPersist(failed);Object.assign(attempt,failed);return;
        }
        attempt.message='Envío incierto. No volverá a ejecutarse automáticamente.';
      }
      if(!reserved) throw fault('ATTEMPT_CONSUMED');
      attempt.phase='verifying';
      // Old firmware: no blocking rules exist, so its telephony settings are compared.
      const after=legacySession?await source.readClearResult({password}):
        {log:await driver.readCalls(password),settingsRevision:snapshotOf(await driver.read(password)).revision};
      const log=validateCallHistory(after.log);
      const expected=legacySession?outcome?.settingsRevision:outcome?.beforeRevision;
      const sameRevision=typeof expected==='string'&&after.settingsRevision===expected;
      // An HTTP 2xx alone is never proof: the independent readback must agree.
      const verified=outcome?.configurationPosts===1&&!outcome?.response?.transportError&&
        outcome?.response?.status>=200&&outcome?.response?.status<400&&
        log.total===0&&sameRevision;
      const completed={...attempt,status:verified?'succeeded':'reviewRequired',
        phase:verified?'complete':'uncertain',finishedAt:now(),
        configurationPosts:outcome?.configurationPosts===1?1:null,
        message:verified?'Historial vacío verificado mediante una segunda sesión. '+
          (legacySession?'Configuración telefónica sin cambios.':'Reglas y telefonía sin cambios.'):
          'El borrado no se ha podido verificar. No lo repitas: comprueba el historial antes de actuar.'};
      await clearPersist(completed);Object.assign(attempt,completed);
      // The connect-time snapshot must not show the erased list again.
      if(verified&&legacySession?.legacy)legacySession.legacy={...legacySession.legacy,history:log};
    }catch(error){
      const uncertain={...attempt,status:reserved?'reviewRequired':'failed',phase:'uncertain',
        finishedAt:now(),configurationPosts:reserved?null:0,
        message:reserved?'Resultado incierto; no repetir el borrado.':'No se ha enviado el borrado.'};
      try{await clearPersist(uncertain);Object.assign(attempt,uncertain);}catch{Object.assign(attempt,uncertain);}
    }finally{password=null;release();}
  }

  const handleReadRoute=createReadRoutes({
    json,fault,requireSession,assertCurrentSession,
    getHealth:()=>{expireSessions();return {
      product:'RUX REAROUTER',version:APP_INFO.version,instanceId:lock.instanceId,
      busy:!!activeWork,workKind:activeWork?.kind??null,
      sessionActive:!!authorizedSessionId,
      lastLocalConnectGuard,lastLocalConnectOriginKind,lastLocalConnectFetchSite};},
    publicNetworkInfo,routerSettings,localRouterNameLookup,projectRouterDeviceInfo,
    getAuthorizedSessionId:()=>authorizedSessionId,
    getActiveWork:()=>activeWork,
    unresolved,driver,routerWork,
    clearReview,lastClear,clearPublic,pendingClear,
    recent,publicOperation,snapshotOf,reconcile,stateView,
    getCached:()=>cached,setCached:value=>{cached=value}
  });

  const dnsWorkflow=await createDnsWorkflow({
    dataDir,driver,requireSession,routerWork,assertCurrentSession,json,bodyOf,
    objectBody,fault,unresolved,otherReview:clearReview,planTtlMs,
    relayProbe,getRouterIp:()=>routerSettings.get().routerIp
  });
  const server = http.createServer(async (req, res) => {
    req.rearouterResponse = res;
    // This marker describes acceptance of this HTTP attempt. The UI correlates
    // it with its single POST, including rejection before the body can be read.
    let commitAccepted = req.method === 'POST' && req.url === '/api/commit' ? false : undefined;
    // Non-sensitive classification; no raw headers, credentials or tokens.
    // Existing security guards are preserved and never bypassed.
    // Classify the origin without storing or returning its literal value.
    const originKind = () => {
      const value = req.headers.origin;
      if (value === undefined) return 'MISSING';
      if (value === '') return 'EMPTY';
      if (value === 'null') return 'NULL';
      if (typeof value !== 'string') return 'INVALID';
      try {
        const actual = new URL(value);
        const expected = new URL(boundOrigin);
        if (actual.origin === expected.origin) return 'MATCHED';
        if (value.toLowerCase() === expected.origin.toLowerCase()) return 'CASE_ONLY';
        if (actual.hostname === expected.hostname && actual.protocol !== expected.protocol)
          return 'LOOPBACK_OTHER_SCHEME';
        if (actual.hostname === expected.hostname && actual.port !== expected.port)
          return 'LOOPBACK_OTHER_PORT';
        if (actual.hostname === 'localhost') return 'LOCALHOST';
        if (actual.hostname === '127.0.0.1') return 'OTHER_LOOPBACK';
        return 'OTHER_ORIGIN';
      } catch { return 'INVALID'; }
    };
    const denyGuard = reason => {
      if (req.method === 'POST' && req.url === '/api/connect') {
        lastLocalConnectGuard = reason;
        if (reason === 'ORIGIN') {
          lastLocalConnectOriginKind = originKind();
          const site = req.headers['sec-fetch-site'];
          lastLocalConnectFetchSite =
            ['same-origin','same-site','cross-site','none'].includes(site) ? site : 'OTHER_OR_MISSING';
        } else {
          lastLocalConnectOriginKind = null;
          lastLocalConnectFetchSite = null;
        }
      }
      res.setHeader('X-Rearouter-Guard', reason);
      throw fault('FORBIDDEN', 403);
    };
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('Referrer-Policy', 'no-referrer');
    res.setHeader('Cross-Origin-Resource-Policy', 'same-origin');
    res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'");
    try {
      if (stopping) throw fault('STOPPING', 503);
      const expectedHost = new URL(boundOrigin).host;
      if (req.headers.host !== expectedHost || !req.url?.startsWith('/') || req.url.startsWith('//')) denyGuard('HOST');
      const url = new URL(req.url, boundOrigin);
      // Navigating to the local SPA with harmless query parameters is valid.
      // Never permit query parameters on authenticated API routes or assets:
      // they must retain their exact request contracts and CSRF checks.
      if (url.origin !== boundOrigin ||
          (url.search && !(req.method==='GET'&&url.pathname==='/'&&url.search.length<=2048)))
        throw fault('BAD_REQUEST');
      // A user-initiated external link may navigate to the public landing page.
      // Keep every API, asset, non-document and non-user navigation blocked.
      const externalUserNavigation = req.method === 'GET' && url.pathname === '/' &&
        req.headers['sec-fetch-mode'] === 'navigate' &&
        req.headers['sec-fetch-dest'] === 'document' &&
        req.headers['sec-fetch-user'] === '?1';
      if (req.headers['sec-fetch-site'] === 'cross-site' && !externalUserNavigation)
        denyGuard('FETCH_SITE');
      const route = url.pathname;
      // A legacy session reaches only the routes its own adapter implements
      // (native contracts of the old firmware); blocking, DNS writes and the
      // polling monitor (one native login per poll) stay closed.
      const limitedSession=sessionFor(req);
      if(limitedSession?.legacy && route.startsWith('/api/')){
        const allowGet=req.method==='GET'&&
          (['/api/health','/api/session','/api/settings','/api/router/legacy/info',
            '/api/phones/autodial','/api/calls/clear/status'].includes(route)||
           (route==='/api/calls'&&req.headers['x-rearouter-monitor']!=='1'));
        const allowPost=req.method==='POST'&&['/api/disconnect','/api/legacy/refresh',
          '/api/phones/autodial/prepare','/api/phones/autodial/commit','/api/phones/ring-test',
          '/api/calls/clear/prepare','/api/calls/clear/commit','/api/calls/clear/reconcile'].includes(route);
        if(!allowGet&&!allowPost)throw fault('LEGACY_READ_ONLY',403);
      }
      if (req.method === 'POST') {
        // Some privacy-aware browsers emit Origin: null even on a genuine
        // same-origin fetch. Only trust that form when browser-controlled Fetch
        // Metadata explicitly confirms SAME origin. Host, session cookie and
        // CSRF are still independently required. All missing/foreign origins
        // and cross-site requests remain denied.
        const strictOrigin = req.headers.origin === boundOrigin;
        const browserSameOriginNull = req.headers.origin === 'null' &&
          req.headers['sec-fetch-site'] === 'same-origin';
        if (!strictOrigin && !browserSameOriginNull) denyGuard('ORIGIN');
        const session = requireSession(req);
        if (!equalSecret(req.headers['x-rearouter-csrf'], session.csrf)) denyGuard('CSRF');
        if (route === '/api/connect') {
          // A passed local preflight supersedes a previous rejected request.
          lastLocalConnectGuard = null;
          lastLocalConnectOriginKind = null;
          lastLocalConnectFetchSite = null;
        }
      }
      if(await serveStaticResource(req,res,route,{publicDir,fault}))return;
      if(await dnsWorkflow.handle(req,res,route))return;
      if(await handleReadRoute(req,res,route))return;
      if (req.method === 'GET' && route === '/api/session') {
        let session = sessionFor(req);
        if (!session) {
          if (sessions.size >= 64) throw fault('BUSY', 503);
          session = {id: randomBytes(32).toString('base64url'), csrf: randomBytes(32).toString('base64url'), password: null, expiresAt: Date.now() + sessionTtlMs};
          sessions.set(session.id, session);
          renewSession(session);
          res.setHeader('Set-Cookie', `${cookieName}=${session.id}; Path=/; HttpOnly; SameSite=Strict`);
        }
        res.rearouterSession = session;
        json(res, 200, sessionView(session)); return;
      }
      if (req.method === 'POST' && route === '/api/settings/detect') {
        requireSession(req); objectBody(await bodyOf(req),[]);
        if (authorizedSessionId) throw fault('SETTINGS_CONNECTED',409);
        // Local route discovery neither owns the router lock nor changes its IP.
        // Concurrent anonymous windows share one bounded OS routing-table read.
        if (!gatewayDetection) {
          gatewayDetection = Promise.resolve().then(() => detectGateway());
          void gatewayDetection.then(() => { gatewayDetection = null; }, () => { gatewayDetection = null; });
        }
        const result=await gatewayDetection;
        if (authorizedSessionId) throw fault('SETTINGS_CONNECTED',409);
        json(res,200,result); return;
      }
      if (req.method === 'POST' && route === '/api/settings') {
        requireSession(req);
        const body=objectBody(await bodyOf(req),['routerIp']);
        const ip=validateRouterIp(body.routerIp);
        if(authorizedSessionId) throw fault('SETTINGS_CONNECTED',409);
        if(unresolved()) throw fault('REVIEW_REQUIRED',409);
        if(typeof driver.setRouterIp!=='function') throw fault('SETTINGS_UNSUPPORTED',400);
        const value=await routerWork('settings',async()=>{
          const saved=await routerSettings.save(ip);
          driver.setRouterIp(saved.routerIp);
          plans.clear(); cached=null;
          return saved;
        }, req);
        json(res,200,{...value,canChange:true}); return;
      }
      if(req.method==='GET' && route==='/api/router/legacy/info'){
        const session=requireSession(req);
        if(!session.legacy||authorizedSessionId!==session.id)
          throw fault('NOT_AUTHENTICATED',401);
        json(res,200,{...session.legacy,configurationPosts:0});return;
      }
      if(req.method==='POST'&&route==='/api/legacy/refresh'){
        const session=requireSession(req,true);
        objectBody(await bodyOf(req),[]);
        if(!session.legacy)throw fault('NOT_AUTHENTICATED',401);
        const pinnedIp=routerSettings.get().routerIp;
        let diagnostic;
        try{
          diagnostic=await routerWork('legacy-refresh',signal=>
            driver.connectLegacy({password:session.password,ip:pinnedIp,signal}),req);
        }catch(error){
          // A router that now rejects the retained password must not get it again.
          if(sessions.get(session.id)===session&&session.legacy)
            session.legacy=legacyRefreshFailed(session.legacy,safeCode(error));
          if(error?.code==='LEGACY_READBACK_NOT_AUTHENTICATED')invalidateSession(session,false);
          throw error;
        }
        assertCurrentSession(session,true);
        if(routerSettings.get().routerIp!==pinnedIp||diagnostic?.authentication!=='VERIFIED'||
           diagnostic?.readOnly!==true||diagnostic?.configurationPosts!==0||
           diagnostic?.family!=='livebox-fibra-legacy')
          throw fault('LEGACY_LOGIN_UNVERIFIED',502);
        session.legacy=mergeLegacyReadback(session.legacy,diagnostic);
        json(res,200,sessionView(session));return;
      }
      if(req.method==='GET'&&route==='/api/router/profile'){
        requireSession(req);
        if(typeof driver.identifyProfile!=='function')
          throw fault('LEGACY_PROFILE_UNAVAILABLE',501);
        const identified=await routerWork('identify-router',signal=>driver.identifyProfile({signal}),req);
        json(res,200,{...identified,readOnly:true,authenticationAttempts:0});
        return;
      }
      if (req.method === 'POST' && route === '/api/connect') {
        const session = requireSession(req);
        const body = objectBody(await bodyOf(req), ['password']);
        if (typeof body.password !== 'string' || !body.password || body.password.length > 256) throw fault('CREDENTIAL_REQUIRED');
        if (authorizedSessionId && authorizedSessionId !== session.id) throw fault('SESSION_IN_USE', 409);
        try {
          const pinnedIp=routerSettings.get().routerIp;
          const profile=typeof driver.identifyProfile==='function'
            ? await routerWork('identify-router',signal=>driver.identifyProfile({signal}),req)
            : null;
          if(routerSettings.get().routerIp!==pinnedIp)
            throw fault('LEGACY_PROFILE_UNKNOWN',409);
          if(profile?.family==='unknown')throw fault('LEGACY_PROFILE_UNKNOWN',409);
          if(profile?.family==='livebox-fibra-legacy'){
            if(typeof driver.connectLegacy!=='function')
              throw fault('LEGACY_PROFILE_UNKNOWN',501);
            const diagnostic=await routerWork('legacy-connect',signal=>
              driver.connectLegacy({password:body.password,ip:pinnedIp,signal}),req);
            assertCurrentSession(session);
            if(routerSettings.get().routerIp!==pinnedIp||
               diagnostic?.authentication!=='VERIFIED'||diagnostic?.readOnly!==true||
               diagnostic?.configurationPosts!==0||diagnostic?.family!==profile.family)
              throw fault('LEGACY_LOGIN_UNVERIFIED',502);
            // Like the modern profile, the password lives only in this local
            // session's memory until disconnect/expiry; each legacy operation is
            // one native login and logout, never an automatic retry.
            session.password=body.password;session.legacy=diagnostic;
            session.profile={family:profile.family,fingerprint:profile.fingerprint??null};
            authorizedSessionId=session.id;cached=null;
            res.rearouterAuthenticated=true;
            json(res,200,sessionView(session));return;
          }
          const snapshot = await routerWork('connect', async signal => {
            const value = snapshotOf(await driver.read(body.password, {signal}));
            signal.throwIfAborted(); assertCurrentSession(session);
            await reconcile(value);
            return value;
          }, req);
          assertCurrentSession(session);
          session.password = body.password;session.legacy=null;
          session.profile=profile?{family:profile.family,fingerprint:profile.fingerprint??null}:null;
          authorizedSessionId = session.id; cached = snapshot;
          res.rearouterAuthenticated = true;
          json(res, 200, sessionView(session)); return;
        } finally { body.password = null; }
      }
      if (req.method === 'POST' && route === '/api/disconnect') {
        const session = requireSession(req);
        objectBody(await bodyOf(req), []);
        if (activeWork) throw fault('BUSY', 409);
        invalidateSession(session, false);
        json(res, 200, {authenticated: false}); return;
      }
      if(req.method==='GET'&&route==='/api/phones/autodial'){
        const session=requireSession(req,true);
        if(typeof adapter(session).readAutodial!=='function')throw fault('AUTODIAL_UNAVAILABLE',501);
        const value=await routerWork('autodial-read',signal=>adapter(session).readAutodial({
          password:session.password,signal
        }),req);
        assertCurrentSession(session,true);
        if(autodialReview&&!autodialReview.unknown){
          const desired=autodialReview.value;
          const actual=autodialReview.type==='enable'?(value.enabled?'1':'0')
            :autodialReview.type==='number'?value.number:String(value.seconds);
          if(actual===desired||value.revision===autodialReview.revision){
            const status=actual===desired?'verified':'notApplied';
            try{
              await exclusiveJson(path.join(autodialDir,autodialReview.id,'result.json'),{
                version:1,status,observedAt:now(),revision:value.revision});
              autodialReview=null;
            }catch{ /* Failed proof persistence retains the review state. */ }
          }
        }
        json(res,200,{...publicAutodial(value),reviewRequired:!!autodialReview});return;
      }
      if(req.method==='POST'&&route==='/api/phones/autodial/prepare'){
        const session=requireSession(req,true);
        if(session.legacy&&session.legacy.capabilities?.autodialWrite!==true)
          throw fault('AUTODIAL_UNAVAILABLE',501);
        const body=objectBody(await bodyOf(req),['type','value','revision']);
        if(typeof body.revision!=='string'||!/^[a-f0-9]{64}$/.test(body.revision))
          throw fault('BAD_REQUEST');
        if(typeof adapter(session).readAutodial!=='function'||typeof adapter(session).applyAutodial!=='function')
          throw fault('AUTODIAL_UNAVAILABLE',501);
        if(autodialReview||unresolved()||clearReview())throw fault('AUTODIAL_REVIEW',409);
        const action=validateAutodialUpdate(body.type,body.value);
        const before=await routerWork('autodial-prepare',signal=>adapter(session).readAutodial({
          password:session.password,signal
        }),req);
        if(before.revision!==body.revision)throw fault('AUTODIAL_STALE',409);
        const change=autoDialChanges(before,action.type,body.value);
        assertCurrentSession(session,true);
        const planId=randomUUID();
        const expiresAt=Date.now()+planTtlMs;
        autodialPlans.set(planId,{id:planId,sessionId:session.id,
          type:action.type,value:action.value,revision:before.revision,
          previous:change.previous,expiresAt,consumed:false});
        for(const [id,p] of autodialPlans)if(p.expiresAt<Date.now()&&!p.consumed)autodialPlans.delete(id);
        const label=change.type==='enable'?(action.value==='1'?'activar':'desactivar')+' el automarcado'
          :change.type==='number'?'guardar el número de destino'
          :'guardar el temporizador';
        json(res,200,{planId,expiresAt:new Date(expiresAt).toISOString(),
          summary:'Se va a '+label+'. Solo se modificarán dos campos nativos del ajuste seleccionado.'});
        return;
      }
      if(req.method==='POST'&&route==='/api/phones/autodial/commit'){
        const session=requireSession(req,true);
        if(session.legacy&&session.legacy.capabilities?.autodialWrite!==true)
          throw fault('AUTODIAL_UNAVAILABLE',501);
        const body=objectBody(await bodyOf(req),['planId']);
        const plan=typeof body.planId==='string'?autodialPlans.get(body.planId):null;
        if(!plan||plan.sessionId!==session.id)throw fault('PLAN_NOT_FOUND',404);
        if(plan.consumed)throw fault('ATTEMPT_CONSUMED',409);
        if(plan.expiresAt<Date.now())throw fault('PLAN_EXPIRED',409);
        if(autodialReview||unresolved()||clearReview())throw fault('AUTODIAL_REVIEW',409);
        plan.consumed=true;
        let reserved=false;
        try{
          const attempt=await routerWork('autodial-write',async signal=>{
            return adapter(session).applyAutodial({password:session.password,signal,
              type:plan.type,
              value:plan.type==='enable'?plan.value==='1':plan.type==='timeout'?Number(plan.value):plan.value,
              expectedRevision:plan.revision,
              beforeDispatch:async()=>{
                signal.throwIfAborted();
                assertCurrentSession(session,true);
                const folder=path.join(autodialDir,plan.id);
                await fs.mkdir(folder,{mode:0o700});
                const receipt={version:1,id:plan.id,type:plan.type,value:plan.value,
                  previous:plan.previous,revision:plan.revision,createdAt:now()};
                await exclusiveJson(path.join(folder,'reservation.json'),receipt);
                autodialReview=receipt;reserved=true;
              }
            });
          },req);
          if(attempt?.configurationPosts!==1){
            if(!reserved)throw fault('AUTODIAL_FORM_MISMATCH',409);
            json(res,202,{submitted:false,verified:false,
              message:'No se puede asegurar el envío. Consulta el estado antes de intentar otra vez.'});return;
          }
          json(res,202,{submitted:true,verified:false,
            message:'Solicitud enviada. Se leerá de nuevo el router para comprobar el cambio.'});return;
        }catch(error){
          // Once reserved, any timeout/transport loss is uncertain. Never replay.
          if(reserved){
            json(res,202,{submitted:false,verified:false,
              message:'Resultado incierto. Consulta el estado; no repitas automáticamente la operación.'});
            return;
          }
          throw error;
        }
      }
      if (req.method === 'POST' && route === '/api/phones/ring-test') {
        const session=requireSession(req,true);
        if(session.legacy&&session.legacy.capabilities?.ringTest!==true)
          throw fault('RING_TEST_UNAVAILABLE',501);
        objectBody(await bodyOf(req),[]);
        if(typeof adapter(session).ringTest!=='function')throw fault('RING_TEST_UNAVAILABLE',501);
        if(unresolved()||clearReview())throw fault('REVIEW_REQUIRED',409);
        if(cached?.compatibility?.safeWrites===false)throw fault('COMPAT_READ_ONLY',409);
        if(lastRingTestAt && Date.now()-lastRingTestAt<60_000)
          throw fault('RING_TEST_COOLDOWN',429);
        // Explicit user action only. Exclusive lock prevents competing operations.
        // The timestamp is reserved BEFORE the one native POST, also on uncertain replies.
        const result=await routerWork('ring-test',signal=>adapter(session).ringTest({
          password:session.password,signal,
          beforeDispatch:()=>{
            signal.throwIfAborted();
            assertCurrentSession(session,true);
            lastRingTestAt=Date.now();
          }
        }),req);
        assertCurrentSession(session,true);
        const response=result?.response;
        const sent=result?.configurationPosts===1;
        if(!sent||response?.transportError===true||response?.status!==200){
          json(res,202,{requested:sent,ringingVerified:false,
            message:'La respuesta no confirma el timbrado físico. Comprueba los teléfonos; no repitas la prueba automáticamente.'});
          return;
        }
        json(res,200,{requested:true,ringingVerified:false,
          message:'El Livebox recibió la solicitud de prueba. Comprueba si suenan los teléfonos conectados.'});
        return;
      }
      if (req.method === 'POST' && route === '/api/calls/clear/prepare') {
        const session=requireSession(req,true);
        objectBody(await bodyOf(req),[]);
        const source=adapter(session);
        if(typeof source.clearCalls!=='function')throw fault('CLEAR_UNAVAILABLE',501);
        if(clearReview())throw fault('CLEAR_REVIEW',409);
        if(unresolved())throw fault('REVIEW_REQUIRED',409);
        if(session.legacy?session.legacy.capabilities?.clearHistory!==true:
           cached?.compatibility?.features?.clearHistory===false)throw fault('COMPAT_READ_ONLY',409);
        // Read only: the plan keeps a count and a hash, never the numbers.
        const log=await routerWork('history-clear-prepare',async signal=>
          validateCallHistory(await source.readCalls(session.password,{signal})),req);
        assertCurrentSession(session,true);
        if(log.total===0)throw fault('CALL_LOG_EMPTY',409);
        const markKey=randomBytes(32);
        const plan={id:randomUUID(),sessionId:session.id,expiresAt:Date.now()+60_000,
          observedCount:log.total,revision:callHistoryRevision(log),
          marks:callMarks(log,{key:markKey}),markKey,consumed:false};
        for(const [id,p] of clearPlans)if(p.sessionId===session.id||p.expiresAt<=Date.now()){
          p.markKey?.fill(0);
          clearPlans.delete(id);
        }
        clearPlans.set(plan.id,plan);
        json(res,200,{token:plan.id,expiresAt:new Date(plan.expiresAt).toISOString(),
          count:log.total,warning:'Se eliminarán TODAS las llamadas registradas: perdidas, entrantes y salientes. '+
            (session.legacy?'No se modificará la configuración telefónica.':'No se modificarán reglas de bloqueo.')});return;
      }
      if (req.method === 'POST' && route === '/api/calls/clear/commit') {
        const session=requireSession(req,true);
        const body=objectBody(await bodyOf(req),['token','confirmation']);
        if(typeof body.token!=='string'||!uuid.test(body.token)||body.confirmation!=='VACIAR_REGISTRO_COMPLETO')
          throw fault('CLEAR_CONFIRMATION');
        const plan=clearPlans.get(body.token);
        if(!plan||plan.sessionId!==session.id)throw fault('PLAN_NOT_FOUND',404);
        if(plan.consumed) {
          const previous=[...clearAttempts.values()].find(a=>a.planId===plan.id);
          if(!previous)throw fault('CLEAR_REVIEW',409);
          json(res,202,{attempt:clearPublic(previous)});return;
        }
        if(plan.expiresAt<=Date.now())throw fault('PLAN_EXPIRED',409);
        if(clearReview())throw fault('CLEAR_REVIEW',409);
        if(unresolved())throw fault('REVIEW_REQUIRED',409);
        if(session.legacy?session.legacy.capabilities?.clearHistory!==true:
           cached?.compatibility?.features?.clearHistory===false)throw fault('COMPAT_READ_ONLY',409);
        const source=adapter(session);
        if(typeof source.clearCalls!=='function'||
           (session.legacy&&typeof source.readClearResult!=='function'))throw fault('CLEAR_UNAVAILABLE',501);
        const release=claimWork('mutation'),password=session.password;
        plan.consumed=true;
        const attempt={id:randomUUID(),planId:plan.id,createdAt:now(),
          observedCount:plan.observedCount,status:'running',phase:'preparing',
          message:'Borrado reservado una sola vez; pendiente de confirmación del Livebox.',
          configurationPosts:null};
        clearAttempts.set(attempt.id,attempt);
        // Binds the attempt to the confirmed list and this router, so a later
        // reconciliation can relate an independent read to it. No password.
        const journal={version:3,historyRevision:plan.revision,marks:plan.marks,
          keySha256:sha(plan.markKey),marksSha256:sha(JSON.stringify(plan.marks)),
          binding:{profile:session.legacy?'legacy':'modern',routerIp:routerSettings.get().routerIp,
            family:/^[a-z0-9-]{1,64}$/.test(session.profile?.family??'')?session.profile.family:null,
            fingerprint:HEX64.test(session.profile?.fingerprint??'')?session.profile.fingerprint:null}};
        try {
          await fs.mkdir(clearPath(attempt),{mode:0o700});
          // Persist the random attempt key separately from the JSON receipt.
          // No router POST can happen before both synced files exist.
          await exclusiveKey(path.join(clearPath(attempt),'marks.key'),plan.markKey);
          await exclusiveJson(path.join(clearPath(attempt),'reservation.json'),
            {version:3,id:attempt.id,planId:plan.id,createdAt:attempt.createdAt,
              observedCount:attempt.observedCount,historyRevision:journal.historyRevision,
              marks:journal.marks,markAlgorithm:'hmac-sha256-v3',
              keySha256:journal.keySha256,marksSha256:journal.marksSha256,
              binding:journal.binding});
          attempt.journal=journal;
          plan.markKey.fill(0);plan.markKey=null;
        }catch{
          plan.markKey?.fill(0);plan.markKey=null;
          // No job was started: nothing can have been sent. Remove only our own folder.
          await fs.rm(clearPath(attempt),{recursive:true,force:true}).catch(()=>{});
          Object.assign(attempt,{status:'failed',phase:'complete',finishedAt:now(),configurationPosts:0,
            message:'Reserva local incompleta; no se ha enviado ningún borrado.'});
          release();throw fault('LOCAL_STORAGE',503);
        }
        const job=runHistoryClear(attempt,password,release,{source,
          legacySession:session.legacy?session:null,expectedRevision:plan.revision});
        jobs.add(job);void job.finally(()=>jobs.delete(job));
        json(res,202,{attempt:clearPublic(attempt)});return;
      }
      // Resolve a clear in review from its journal and independent reads only.
      // Never sends a configuration POST; never retries the clear.
      if (req.method === 'POST' && route === '/api/calls/clear/reconcile') {
        const session=requireSession(req,true);
        const body=objectBody(await bodyOf(req),['attemptId']);
        if(typeof body.attemptId!=='string'||!uuid.test(body.attemptId))throw fault('BAD_REQUEST');
        const attempt=clearAttempts.get(body.attemptId);
        if(!attempt)throw fault('CLEAR_ATTEMPT_UNKNOWN',404);
        if(attempt.status==='running')throw fault('BUSY',409);
        if(attempt.status!=='reviewRequired'){json(res,200,{attempt:clearPublic(attempt),resolved:true});return;}
        const journal=attempt.journal,source=adapter(session);
        if([2,3].includes(journal?.version)&&(journal.binding.profile!==(session.legacy?'legacy':'modern')||
           journal.binding.routerIp!==routerSettings.get().routerIp))throw fault('CLEAR_ROUTER_MISMATCH',409);
        const check=await routerWork('history-clear-reconcile',async signal=>{
          if(attempt.status!=='reviewRequired')return null;
          let found={outcome:'uncertain',reason:'RECORD_WITHOUT_EVIDENCE',evidence:{}},log=null;
          if([2,3].includes(journal?.version)){
            const dispatch=await clearDispatchOf(attempt);
            // A POST still in flight must not be judged: wait after the last checkpoint.
            if(Date.now()-Date.parse(dispatch.createdAt||attempt.createdAt)<clearSettleMs)throw fault('CLEAR_SETTLING',409);
            if(typeof driver.identifyProfile==='function'){
              const id=await driver.identifyProfile({signal});
              if((journal.binding.family&&id?.family!==journal.binding.family)||
                 (journal.binding.fingerprint&&id?.fingerprint!==journal.binding.fingerprint))
                throw fault('CLEAR_ROUTER_MISMATCH',409);
            }
            const after=session.legacy?await source.readClearResult({password:session.password,signal}):
              {log:await driver.readCalls(session.password,{signal}),
                settingsRevision:snapshotOf(await driver.read(session.password,{signal})).revision};
            log=validateCallHistory(after.log);
            const markKey=journal.version===3?await clearMarkKeyOf(attempt):null;
            try{
              found=classifyClearEvidence({marks:journal.marks,dispatch,log,
                settingsRevision:after.settingsRevision,markKey});
            }finally{markKey?.fill(0)}
          }
          signal.throwIfAborted();assertCurrentSession(session,true);
          const rule=CLEAR_RESOLUTIONS[found.outcome];
          const record={version:1,id:attempt.id,checkedAt:now(),outcome:found.outcome,
            status:rule?.status??null,configurationPosts:rule?rule.configurationPosts:null,
            reason:found.reason??null,message:CLEAR_CHECK_MESSAGES[found.reason||found.outcome]+
              (found.outcome==='cleared'&&log.total?' El router ya registra '+log.total+' llamadas posteriores.':''),
            evidence:found.evidence};
          // The receipt must be on disk before the review is lifted in memory.
          await exclusiveJson(path.join(clearPath(attempt),'reconcile-'+record.checkedAt.replace(/[:.]/g,'-')+
            '-'+randomUUID().slice(0,8)+'.json'),record);
          attempt.lastCheck={checkedAt:record.checkedAt,outcome:record.outcome,message:record.message};
          if(rule){
            Object.assign(attempt,{status:rule.status,phase:'complete',configurationPosts:rule.configurationPosts,
              message:record.message,resolution:{outcome:record.outcome,checkedAt:record.checkedAt}});
            if(found.outcome==='cleared'&&session.legacy)session.legacy={...session.legacy,history:log};
          }
          return {resolved:!!rule,history:rule?log:null};
        },req);
        json(res,200,{attempt:clearPublic(attempt),resolved:check?check.resolved:attempt.status!=='reviewRequired',
          history:check?.history??null});return;
      }
      if (req.method === 'POST' && route === '/api/policy/preview') {
        const session = requireSession(req, true);
        const body = objectBody(await bodyOf(req), ['blocks', 'exceptions', 'samples']);
        // Preview has no plan, permission, journal write, reconciliation or apply path.
        const result = await routerWork('policy-preview', async signal => {
          const snapshot = snapshotOf(await driver.read(session.password, {signal}));
          signal.throwIfAborted(); assertCurrentSession(session, true);
          const state = validateState(snapshot.rows);
          const preview = previewPolicy(body, {
            incoming: state.incoming.map(({id, pattern}) => ({id, pattern})),
            outgoingCount: state.outgoing.length,
            enabledProfiles: state.profiles.filter(profile => profile.enable !== '0').length,
            capacity: 100,
          });
          return {snapshot, preview};
        }, req);
        cached = result.snapshot;
        const view = stateView(result.snapshot);
        json(res, 200, {revision: view.revision, capturedAt: view.capturedAt,
          enabledProfiles: view.enabledProfiles, canWrite: view.canWrite, preview: result.preview}); return;
      }
      if (req.method === 'POST' && route === '/api/plan') {
        const session = requireSession(req, true);
        const body = objectBody(await bodyOf(req), ['type', 'pattern'], ['ruleId']);
        if (!['add', 'delete'].includes(body.type)) throw fault('BAD_REQUEST');
        if (body.type === 'delete') {
          validateRuleId(body.ruleId);
          validateExistingPattern(body.pattern);
        } else {
          validateWritablePattern(body.pattern);
          if (Object.hasOwn(body, 'ruleId')) throw fault('BAD_REQUEST');
        }
        if (unresolved()) throw fault('REVIEW_REQUIRED', 409);
        if(cached?.compatibility?.features?.[body.type]===false)throw fault('COMPAT_READ_ONLY',409);
        const beforeSnapshot = await routerWork('plan', async signal => {
          const snapshot = snapshotOf(await driver.read(session.password, {signal}));
          signal.throwIfAborted(); assertCurrentSession(session, true);
          if(snapshot.compatibility.features[body.type]!==true)throw fault('COMPAT_READ_ONLY',409);
          preflight(snapshot, body); return snapshot;
        }, req);
        assertCurrentSession(session, true);
        cached = beforeSnapshot;
        const plan = {planId: randomUUID(), operationId: randomUUID(), sessionId: session.id,
          type: body.type, pattern: body.pattern, ruleId: body.type === 'delete' ? body.ruleId : null,
          createdAt: now(), expiresAt: new Date(Date.now() + planTtlMs).toISOString(), beforeSnapshot, consumed: false};
        for (const [id, old] of plans) if (!old.consumed && Date.parse(old.expiresAt) < Date.now()) plans.delete(id);
        plans.set(plan.planId, plan);
        json(res, 200, {planId: plan.planId, operationId: plan.operationId, type: plan.type, pattern: plan.pattern,
          ...(plan.type === 'delete' ? {ruleId: plan.ruleId} : {}), expiresAt: plan.expiresAt,
          summary: plan.type === 'add'
            ? isFixedLengthNativePrefix(plan.pattern)
              ? 'Se añadirá UNA máscara nativa para hasta ' + (10 ** (9 - plan.pattern.indexOf('x'))).toLocaleString('es-ES') +
                ' posibles números de nueve cifras. AVISO: únicamente se verificó físicamente una terminación, no toda esta cobertura. Puede bloquear llamadas legítimas. Las demás reglas se conservarán.'
              : 'Se añadirá una única regla para este número exacto. Las demás reglas se conservarán.'
            : 'Se retirará únicamente la regla seleccionada por su ID y texto exactos. Las demás reglas se conservarán.'}); return;
      }
      if (req.method === 'POST' && route === '/api/commit') {
        const session = requireSession(req, true);
        const body = objectBody(await bodyOf(req), ['planId']);
        const plan = typeof body.planId === 'string' ? plans.get(body.planId) : null;
        // A recognized repeat refers to an already accepted operation, even if
        // a new session can no longer retrieve it through this commit request.
        if (plan?.consumed || [...operations.values()].some(operation => operation.planId === body.planId)) commitAccepted = true;
        assertCurrentSession(session, true);
        if (typeof body.planId !== 'string') throw fault('BAD_REQUEST');
        if (!plan || plan.sessionId !== session.id) throw fault('PLAN_NOT_FOUND', 404);
        if (plan.consumed) {
          commitAccepted = true;
          const existing = operations.get(plan.operationId);
          if (!existing) throw fault('REVIEW_REQUIRED', 409);
          json(res, 202, {operation: publicOperation(existing)}); return;
        }
        if (Date.parse(plan.expiresAt) <= Date.now()) throw fault('PLAN_EXPIRED', 409);
        if (unresolved()) throw fault('REVIEW_REQUIRED', 409);
        const release = claimWork('mutation');
        const operationPassword = session.password;
        // From this point onward, any failure can have a durable reservation.
        // Set this before consuming the plan, creating the operation or awaiting I/O.
        commitAccepted = true;
        plan.consumed = true;
        const op = {id: plan.operationId, planId: plan.planId, type: plan.type, pattern: plan.pattern,
          ruleId: plan.ruleId, createdAt: now(), status: 'running', configurationPosts: null,
          message: 'Intento reservado. Se enviará como máximo una acción y se comprobará mediante lectura.',
          beforeSnapshot: plan.beforeSnapshot, checkpoint: null};
        operations.set(op.id, op);
        try {
          await fs.mkdir(directoryOf(op), {mode: 0o700});
          await exclusiveJson(path.join(directoryOf(op), 'reservation.json'), {version: 1, operation: publicOperation(op), beforeSnapshot: op.beforeSnapshot});
        } catch {
          op.status = 'reviewRequired'; op.configurationPosts = 0; op.finishedAt = now();
          op.message = messages.LOCAL_STORAGE + ' No se ha enviado el cambio.';
          release(); throw fault('LOCAL_STORAGE', 503);
        }
        const job = runOperation(op, operationPassword, release);
        jobs.add(job); void job.finally(() => jobs.delete(job));
        json(res, 202, {operation: publicOperation(op)}); return;
      }
      throw fault(route.startsWith('/api/') ? 'METHOD_NOT_ALLOWED' : 'NOT_FOUND', route.startsWith('/api/') ? 405 : 404);
    } catch (error) {
      if (!res.headersSent) {
        const code = safeCode(error);
        const status = Number.isInteger(error?.status) && error.status >= 400 && error.status <= 599 ? error.status
          : ['AUTH_FAILED', 'AUTH_USER', 'NOT_AUTHENTICATED'].includes(code) ? 401 : code === 'ROUTER_TIMEOUT' ? 504 : code === 'ROUTER_UNAVAILABLE' ? 502 : 400;
        json(res, status, {error: {code, message: messages[code],
          ...(commitAccepted === false ? {commitAccepted: false} : {})}});
      } else res.end();
    }
  });
  server.requestTimeout = 15_000;
  server.headersTimeout = 10_000;
  server.keepAliveTimeout = 5000;
  const api = {
    server,
    get origin() { return boundOrigin; },
    async listen() {
      if (server.listening) return api;
      if (closed) throw fault('STOPPING', 503);
      try {
        await new Promise((resolve, reject) => {
          const failed = error => { server.off('listening', ready); reject(error); };
          const ready = () => { server.off('error', failed); resolve(); };
          server.once('error', failed); server.once('listening', ready); server.listen(port, host);
        });
        boundOrigin = `http://${host}:${server.address().port}`;
        return api;
      } catch { await api.close(); throw fault('LOCAL_STORAGE', 503); }
    },
    async close() {
      if (closed) return;
      stopping = true;
      if (activeWork?.kind !== 'mutation') activeWork?.controller?.abort(fault('STOPPING', 503));
      if (server.listening) await new Promise(resolve => { server.close(resolve); server.closeIdleConnections?.(); });
      await Promise.allSettled([...jobs]);
      await Promise.allSettled([...reads]);
      for (const session of sessions.values()) { session.password = null; clearTimeout(session.timer); }
      sessions.clear(); plans.clear(); cached = null; authorizedSessionId = null;
      await releaseLock(); closed = true;
    },
  };
  return api;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const {LiveboxDriver} = await import('./router-client.mjs');
    const root = path.dirname(fileURLToPath(import.meta.url));
    const dataDir = path.join(root, 'data');
    await ensurePrivateDataDir(dataDir);
    const manager = await createManagerServer({driver: new LiveboxDriver({root}), dataDir});
    await manager.listen();
    console.log(`Gestor local disponible en ${manager.origin}`);
    const stop = async () => { await manager.close(); process.exit(0); };
    process.once('SIGINT', stop); process.once('SIGTERM', stop);
  } catch (error) { console.error(messages[safeCode(error)]); process.exitCode = 1; }
}

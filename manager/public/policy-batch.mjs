// RUX REAROUTER: checked exact-number application. No direct router calls or retries of POST.
import {REQUEST_BUDGETS} from './request-budget.mjs';
const MAX_OPERATION_POLLS = Math.ceil((REQUEST_BUDGETS.operationMs + REQUEST_BUDGETS.requestMs) / 1000) + 1;
const DIGITS = /^[0-9]{1,32}$/;
const SHA = /^[a-f0-9]{64}$/;
export const MAX_EXACT_BATCH = 10;
const defaultWait = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
const unavailable = (reason) => ({ready: false, numbers: [], reason});

export function selectExactBatch(preview, state, previewRevision) {
  if (!preview || !state || previewRevision !== state.revision || !SHA.test(String(state.revision || '')))
    return unavailable('Calcula la propuesta con el estado actual del router.');
  if (!Array.isArray(preview.unknownExisting) || !Array.isArray(preview.conflicts) || !preview.capacity ||
      !Array.isArray(state.incoming) || typeof state.canWrite !== 'boolean')
    return unavailable('No se puede validar la propuesta.');
  if (preview.unknownExisting.length || preview.conflicts.length)
    return unavailable('Hay reglas de efecto desconocido o excepciones en conflicto. Revisa la lista antes de aplicar.');
  if (preview.existingConfiguration?.enabledProfiles !== 0)
    return unavailable('No se aplicarán propuestas con perfiles de bloqueo activos.');
  if (!Array.isArray(preview.exactExpansion))
    return unavailable('La propuesta es demasiado amplia para convertirla en números completos.');
  if (preview.exactExpansion.some((value) => typeof value !== 'string' || !DIGITS.test(value)) ||
      new Set(preview.exactExpansion).size !== preview.exactExpansion.length)
    return unavailable('La expansión contiene datos no verificables.');
  const existing = new Set(state.incoming.filter((rule) => rule.exact === true && DIGITS.test(rule.pattern)).map((rule) => rule.pattern));
  const numbers = preview.exactExpansion.filter((number) => !existing.has(number));
  if (!numbers.length) return unavailable('Todos los números exactos de la propuesta ya están registrados.');
  if (numbers.length > MAX_EXACT_BATCH)
    return unavailable('Máximo diez nuevas altas por tanda. Reduce la cobertura o divide la propuesta.');
  if (preview.capacity.exactExpansionFits !== true || state.incoming.length + numbers.length > 100)
    return unavailable('No hay suficientes huecos para todas las altas.');
  if (!state.canWrite)
    return unavailable('El router exige revisar su estado antes de modificarlo.');
  return {ready: true, numbers, reason: 'Se aplicarán ' + numbers.length +
    ' números completos de forma individual. No se enviará ninguna máscara.'};
}

function verifyState(value) {
  if (!value || !SHA.test(String(value.revision || '')) || !Array.isArray(value.incoming) ||
      value.incoming.some((rule) => !rule || typeof rule.id !== 'string' || typeof rule.pattern !== 'string') ||
      typeof value.canWrite !== 'boolean') throw new Error('La lectura del router no es verificable.');
  return value;
}
function ensurePlan(value, number) {
  if (value?.type !== 'add' || value.pattern !== number ||
      typeof value.planId !== 'string' || typeof value.operationId !== 'string' ||
      !Number.isFinite(Date.parse(value.expiresAt)) || Date.parse(value.expiresAt) <= Date.now())
    throw new Error('El plan del siguiente número es inválido.');
  return value;
}
async function waitOperation(api, plan, number, wait, epochValid, polls, deadline, clock) {
  for (let i = 0; i < polls; i += 1) {
    if (!epochValid()) throw new Error('La sesión ha cambiado durante la comprobación.');
    if (clock() >= deadline) throw new Error('La comprobación alcanzó su plazo; el recibo queda pendiente de revisión.');
    const data = await api('/api/operations');
    if (!Array.isArray(data?.operations)) throw new Error('El registro de operaciones no se puede validar.');
    const operation = data.operations.find((item) => item.id === plan.operationId);
    if (operation) {
      if (operation.type !== 'add' || operation.pattern !== number || operation.planId !== plan.planId)
        throw new Error('El resultado no pertenece al plan aprobado.');
      if (operation.status === 'succeeded') {
        if (operation.configurationPosts !== 1 || operation.verification?.ok !== true ||
            operation.verification?.phoneUnchanged !== true ||
            !Array.isArray(operation.verification?.issueCodes) || operation.verification.issueCodes.length !== 0 ||
            typeof operation.verification.ruleId !== 'string')
          throw new Error('El resultado no confirma un alta única con la telefonía intacta.');
        return operation;
      }
      if (operation.status !== 'running')
        throw new Error('El alta requiere revisión o no se ha aplicado. No se continuará.');
    }
    await wait(Math.min(1000, Math.max(0, deadline - clock())));
  }
  throw new Error('La operación no terminó de verificarse. No se repetirá el envío.');
}
async function verifyAfter(api, number, before, wait, epochValid, deadline, clock) {
  for (let i = 0; i < 15; i += 1) {
    if (!epochValid()) throw new Error('La sesión ha cambiado durante la lectura.');
    if (clock() >= deadline) throw new Error('La lectura de verificación alcanzó su plazo.');
    const after = verifyState(await api('/api/state'));
    if (after.canWrite) {
      if (after.incoming.length !== before.incoming.length + 1 ||
          after.incoming.filter((rule) => rule.pattern === number && rule.exact === true).length !== 1 ||
          !before.incoming.every((old) => after.incoming.some((rule) => rule.id === old.id && rule.pattern === old.pattern)))
        throw new Error('El cambio no se limita a la nueva regla. Se detiene la tanda.');
      return after;
    }
    await wait(350);
  }
  throw new Error('No se pudo verificar que el router esté libre para la siguiente regla.');
}
export async function runExactBatch({
  api, numbers, revision, shouldStop = () => false, epochValid = () => true,
  onProgress = () => {}, onApplied = () => {}, wait = defaultWait, polls = MAX_OPERATION_POLLS, clock = Date.now,
} = {}) {
  if (typeof api !== 'function' || typeof shouldStop !== 'function' || typeof epochValid !== 'function' ||
      typeof onProgress !== 'function' || typeof onApplied !== 'function' || typeof wait !== 'function' || typeof clock !== 'function' ||
      !Array.isArray(numbers) || !numbers.length || numbers.length > MAX_EXACT_BATCH ||
      new Set(numbers).size !== numbers.length || numbers.some((n) => typeof n !== 'string' || !DIGITS.test(n)) ||
      !SHA.test(String(revision || '')) || !Number.isInteger(polls) || polls < 1 || polls > MAX_OPERATION_POLLS)
    throw new Error('La tanda solicitada no tiene un formato seguro.');
  const applied = [];
  let commitPending = false, deadline = 0;
  let lastState = null;
  let pendingPlan = null, pendingBefore = null, pendingNumber = null;
  try {
    let state = verifyState(await api('/api/state'));
    lastState = state;
    if (!state.canWrite || state.revision !== revision)
      throw new Error('La lista ha cambiado o requiere revisión; no se ha enviado ninguna alta.');
    for (const number of numbers) {
      if (shouldStop()) return {applied, stopped: true, uncertain: false, lastState};
      if (!epochValid()) throw new Error('La sesión ha cambiado. Se detiene la tanda.');
      if (state.incoming.some((rule) => rule.pattern === number))
        throw new Error('El número ya aparece en la lista. No se duplicará.');
      onProgress({phase: 'plan', applied: applied.length, total: numbers.length});
      const plan = ensurePlan(await api('/api/plan', {method: 'POST', body: {type: 'add', pattern: number}}), number);
      onProgress({phase: 'commit', applied: applied.length, total: numbers.length});
      commitPending = true;
      deadline = clock() + REQUEST_BUDGETS.operationMs + REQUEST_BUDGETS.requestMs;
      pendingPlan = plan;
      pendingBefore = state;
      pendingNumber = number;
      const response = await api('/api/commit', {method: 'POST', body: {planId: plan.planId}});
      if (response?.operation?.id !== plan.operationId || response.operation?.planId !== plan.planId ||
          response.operation?.type !== 'add' || response.operation?.pattern !== number)
        throw new Error('La respuesta de envío no corresponde al plan aprobado.');
      const op = await waitOperation(api, plan, number, wait, epochValid, polls, deadline, clock);
      const after = await verifyAfter(api, number, state, wait, epochValid, deadline, clock);
      applied.push(number);
      lastState = after;
      state = after;
      commitPending = false;
      pendingPlan = pendingBefore = pendingNumber = null;
      onApplied({number, operation: op, state: after, applied: applied.length, total: numbers.length});
      onProgress({phase: 'verified', applied: applied.length, total: numbers.length});
    }
    return {applied, stopped: false, uncertain: false, lastState};
  } catch (error) {
    const originalError = error instanceof Error ? error.message : 'Error no identificado.';
    if (commitPending && pendingPlan && pendingBefore && pendingNumber) {
      // A lost response is reconciled by GET only. Never submit a second commit.
      try {
        const op = await waitOperation(api, pendingPlan, pendingNumber, wait, epochValid, polls, deadline, clock);
        const after = await verifyAfter(api, pendingNumber, pendingBefore, wait, epochValid, deadline, clock);
        applied.push(pendingNumber);
        lastState = after;
        commitPending = false;
        onApplied({number: pendingNumber, operation: op, state: after,
          applied: applied.length, total: numbers.length});
        onProgress({phase: 'verified', applied: applied.length, total: numbers.length});
        return {applied, stopped: true, uncertain: false, lastState,
          error: 'Respuesta perdida, pero el alta se verificó solo con lecturas. No se enviaron más números.'};
      } catch {
        // Unverifiable means stop and require explicit review, not another POST.
      }
    }
    return {applied, stopped: false, uncertain: commitPending, lastState,
      pendingPlan: commitPending && pendingPlan ? {
        planId: pendingPlan.planId, operationId: pendingPlan.operationId,
        pattern: pendingNumber} : null,
      error: originalError + ' No se reenviará el cambio.'};
  }
}

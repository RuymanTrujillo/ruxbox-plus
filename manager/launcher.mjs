import http from 'node:http';
import net from 'node:net';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import {createHash, randomUUID} from 'node:crypto';
import {spawn} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {ensurePrivateDataDir} from './private-storage.mjs';
import {resolveBrowserExecutable} from './browser-runtime.mjs';

const uuid = /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/;
const delay = ms => new Promise(resolve => setTimeout(resolve, ms));
function problem(code, message) { return Object.assign(new Error(message), {code}); }

/** A bounded, read-only probe. It neither creates a web session nor calls the router. */
export function probeManager(port, {timeoutMs = 1200} = {}) {
  return new Promise(resolve => {
    let connected = false, settled = false, watchdog;
    const finish = value => { if (!settled) { settled = true; clearTimeout(watchdog); resolve(value); } };
    const req = http.get({hostname: '127.0.0.1', port, path: '/api/health',
      agent: false, headers: {'Connection': 'close'}}, res => {
      let bytes = 0; const chunks = [];
      res.on('data', chunk => {
        bytes += chunk.length;
        if (bytes > 8192) { finish({kind: 'foreign'}); res.destroy(); }
        else chunks.push(chunk);
      });
      res.on('end', () => {
        try {
          const body = JSON.parse(Buffer.concat(chunks).toString('utf8'));
          if (res.statusCode !== 200 || body.product !== 'RUX REAROUTER' ||
              typeof body.version !== 'string' || !/^\d+\.\d+\.\d+(?:[-+][\w.-]+)?$/.test(body.version) ||
              typeof body.instanceId !== 'string' || !uuid.test(body.instanceId) || typeof body.busy !== 'boolean') {
            finish({kind: 'foreign'}); return;
          }
          finish({kind: 'manager', health: body});
        } catch { finish({kind: 'foreign'}); }
      });
      res.on('error', () => finish({kind: 'unresponsive'}));
    });
    req.on('socket', socket => socket.once('connect', () => { connected = true; }));
    watchdog = setTimeout(() => {
      finish({kind: connected ? 'unresponsive' : 'absent'}); req.destroy();
    }, timeoutMs);
    req.on('error', error => finish({kind: !connected && error.code === 'ECONNREFUSED' ? 'absent' : 'unresponsive'}));
  });
}

async function readLock(dataDir) {
  try {
    const filename = path.join(dataDir, 'instance.lock');
    if ((await fs.stat(filename)).size > 4096) return {kind: 'invalid'};
    const lock = JSON.parse(await fs.readFile(filename, 'utf8'));
    if (!Number.isInteger(lock.pid) || lock.pid < 1 || !uuid.test(lock.instanceId) ||
        !Number.isFinite(Date.parse(lock.startedAt))) return {kind: 'invalid'};
    return {kind: 'present', lock};
  } catch (error) { return {kind: error.code === 'ENOENT' ? 'absent' : 'invalid'}; }
}

// After a Windows reboot, a lock created before the current boot cannot
// describe a live instance. Retain every other lock, including uncertain
// crashes in this boot and locks whose PID cannot be proved absent.
async function recoverPrebootLock(dataDir, state, port) {
  if (process.platform !== 'win32' || state.kind !== 'present') return false;
  const uptime = os.uptime(), started = Date.parse(state.lock.startedAt);
  const boot = Date.now() - uptime * 1000;
  if (!Number.isFinite(uptime) || uptime < 0 || !Number.isFinite(started) ||
      started >= boot - 120_000) return false;
  try { process.kill(state.lock.pid, 0); return false; }
  catch (error) { if (error?.code !== 'ESRCH') return false; }

  const filename = path.join(dataDir, 'instance.lock');
  try {
    // Require the same private ACL that a normal launch would require.
    await ensurePrivateDataDir(dataDir);
    const stat = await fs.lstat(filename);
    if (!stat.isFile() || stat.isSymbolicLink() || stat.size > 4096) return false;
    const original = await fs.readFile(filename, 'utf8');
    const current = JSON.parse(original);
    if (current.pid !== state.lock.pid || current.instanceId !== state.lock.instanceId ||
        current.startedAt !== state.lock.startedAt) return false;
    // Keep the port check immediately adjacent to the sole removal.
    if ((await probeManager(port)).kind !== 'absent' ||
        (await fs.readFile(filename, 'utf8')) !== original) return false;
    await fs.unlink(filename);
    return true;
  } catch { return false; }
}

async function verifyHealth(probe, dataDir) {
  if (probe.kind !== 'manager') return false;
  const state = await readLock(dataDir);
  return state.kind === 'present' && state.lock.instanceId === probe.health.instanceId;
}

async function completeLaunch(dataDir, port) {
  const filename = path.join(dataDir, 'launch.pending.json');
  try {
    const value = JSON.parse(await fs.readFile(filename, 'utf8'));
    if (value.owner === 'RUX REAROUTER launcher' && value.port === port && uuid.test(value.attemptId)) {
      // This is completion of our successful launch journal, never an instance
      // lock removal to force a start. Unverified or foreign markers are retained.
      await fs.unlink(filename);
    }
  } catch (error) { if (error.code !== 'ENOENT') return; }
}

async function abandonUndispatchedLaunch(dataDir, port, attemptId) {
  const filename = path.join(dataDir, 'launch.pending.json');
  try {
    if ((await fs.stat(filename)).size > 4096) return;
    const value = JSON.parse(await fs.readFile(filename, 'utf8'));
    // A missing executable or an OS spawn error proves that this attempt never
    // created a child. Only its exact journal may be removed; an older, foreign
    // or replaced marker remains untouched.
    if (value.owner === 'RUX REAROUTER launcher' && value.port === port &&
        value.attemptId === attemptId) await fs.unlink(filename);
  } catch { /* If ownership cannot be proved, retain the marker. */ }
}

function coordinationAddress(dataDir, port) {
  const key = createHash('sha256').update(path.resolve(dataDir).toLowerCase() + ':' + port).digest('hex').slice(0, 32);
  // The pipe exists only while this launcher is starting/checking the process.
  // Windows releases it automatically if a launcher exits or crashes.
  return process.platform === 'win32' ? '\\\\.\\pipe\\rearouter-launch-' + key
    : path.join(os.tmpdir(), 'rearouter-launch-' + key + '.sock');
}

async function claimLaunch(address) {
  const coordinator = net.createServer(socket => socket.end());
  try {
    await new Promise((resolve, reject) => {
      coordinator.once('error', reject); coordinator.listen(address, resolve);
    });
    return coordinator;
  } catch (error) {
    coordinator.close();
    if (error.code === 'EADDRINUSE') return null;
    throw problem('LAUNCH_COORDINATION', 'No se ha podido coordinar el inicio del gestor.');
  }
}

async function startManager({managerDir, dataDir, nodePath, serverScript}) {
  let stdout, stderr, spawned = false;
  try {
    await fs.access(nodePath); await fs.access(serverScript);
    const logs = path.join(dataDir, 'logs'); await fs.mkdir(logs, {recursive: true});
    const label = 'launcher-' + new Date().toISOString().replace(/[:.]/g, '-') + '-' + randomUUID();
    stdout = await fs.open(path.join(logs, label + '.out.log'), 'ax', 0o600);
    stderr = await fs.open(path.join(logs, label + '.err.log'), 'ax', 0o600);
    const child = spawn(nodePath, [serverScript], {cwd: managerDir, detached: true,
      windowsHide: true, stdio: ['ignore', stdout.fd, stderr.fd]});
    await new Promise((resolve, reject) => {
      child.once('spawn', () => { spawned = true; resolve(); });
      child.once('error', reject);
    });
    child.unref();
    return child.pid;
  } catch (error) {
    if (!spawned) error.launchNotDispatched = true;
    throw error;
  } finally {
    // Closing our local log handles must not disguise whether spawn happened.
    await Promise.allSettled([stdout?.close(), stderr?.close()].filter(Boolean));
  }
}

/** Only a proven preboot Windows lock can be removed; no retries or process termination. */
export async function ensureManager({managerDir = path.dirname(fileURLToPath(import.meta.url)),
  dataDir = path.join(managerDir, 'data'), nodePath = process.execPath,
  serverScript = path.join(managerDir, 'server.mjs'), port = 8765,
  startupTimeoutMs = 15_000, pollMs = 200} = {}) {
  if (!Number.isInteger(port) || port < 1 || port > 65535 || !Number.isFinite(startupTimeoutMs) ||
      startupTimeoutMs < 1 || !Number.isFinite(pollMs) || pollMs < 1) throw problem('BAD_OPTIONS', 'Opciones de inicio no válidas.');
  const origin = `http://127.0.0.1:${port}`;
  const initial = await probeManager(port);
  if (await verifyHealth(initial, dataDir)) {
    await completeLaunch(dataDir, port);
    return {status: 'existing', origin, started: false};
  }
  if (initial.kind === 'foreign' || initial.kind === 'manager') {
    throw problem('FOREIGN_PORT', `El puerto ${port} responde, pero no corresponde a esta instalación de RUX REAROUTER.`);
  }
  if (initial.kind === 'unresponsive') throw problem('UNRESPONSIVE_PORT', `El puerto ${port} está ocupado, pero no ofrece una respuesta verificable del gestor.`);
  const coordinator = await claimLaunch(coordinationAddress(dataDir, port));
  const deadline = Date.now() + startupTimeoutMs;
  let started = false, pid = null;
  try {
    // Recheck after acquiring the pipe: another launcher may have just finished.
    while (true) {
      const probe = await probeManager(port, {timeoutMs: Math.min(1200, startupTimeoutMs)});
      if (await verifyHealth(probe, dataDir)) {
        await completeLaunch(dataDir, port);
        return {status: started ? 'started' : 'existing', origin, started, ...(pid ? {pid} : {})};
      }
      if (probe.kind === 'foreign' || probe.kind === 'manager') throw problem('FOREIGN_PORT', `El puerto ${port} pertenece a otra aplicación o instalación.`);
      const lock = await readLock(dataDir);
      const pendingPath = path.join(dataDir, 'launch.pending.json');
      const pending = await fs.stat(pendingPath).then(() => true, error => { if (error.code === 'ENOENT') return false; throw error; });
      if (coordinator && !started && !pending && probe.kind === 'absent' &&
          lock.kind === 'present' && await recoverPrebootLock(dataDir, lock, port)) {
        continue;
      }
      if (coordinator && !started && !pending && probe.kind === 'absent' && lock.kind === 'absent') {
        await fs.access(nodePath); await fs.access(serverScript);
        // The bundled product requires a local Chromium executable. Fail
        // BEFORE writing launch.pending.json, preserving a clean retry.
        if(path.resolve(serverScript)===path.join(path.resolve(managerDir),'server.mjs'))
          resolveBrowserExecutable();
        await ensurePrivateDataDir(dataDir);
        const attemptId = randomUUID();
        const journal = await fs.open(pendingPath, 'wx', 0o600);
        try {
          await journal.writeFile(JSON.stringify({owner: 'RUX REAROUTER launcher', attemptId,
            port, createdAt: new Date().toISOString(), launcherPid: process.pid}));
          await journal.sync();
        } finally { await journal.close(); }
        try { pid = await startManager({managerDir, dataDir, nodePath, serverScript}); }
        catch (error) {
          if (error.launchNotDispatched === true) await abandonUndispatchedLaunch(dataDir, port, attemptId);
          throw error;
        }
        started = true;
      }
      if (Date.now() >= deadline) {
        if (pending && lock.kind === 'absent') throw problem('START_PENDING', 'Un inicio anterior está pendiente de comprobar. No se repetirá ni se borrará su marcador automáticamente.');
        if (lock.kind !== 'absent') throw problem('INSTANCE_LOCKED', 'Existe un bloqueo de instancia y el gestor no está disponible. Se conserva el bloqueo; revisa el proceso y sus registros.');
        throw problem(started ? 'START_TIMEOUT' : 'LAUNCH_BUSY', started
          ? 'El gestor no respondió dentro del plazo de inicio. No se ha repetido el arranque; revisa sus registros.'
          : 'Otro lanzador está comprobando o iniciando el gestor. No se ha creado una segunda instancia.');
      }
      await delay(Math.min(pollMs, Math.max(1, deadline - Date.now())));
    }
  } finally {
    if (coordinator) await new Promise(resolve => coordinator.close(resolve));
  }
}

function openInterface(origin) {
  const child = process.platform === 'win32'
    ? spawn('cmd.exe', ['/d', '/s', '/c', 'start', '""', origin], {windowsHide: true, detached: true, stdio: 'ignore'})
    : spawn('xdg-open', [origin], {detached: true, stdio: 'ignore'});
  child.on('error', () => { console.error('No se pudo abrir el navegador. Abre ' + origin); });
  child.unref();
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const result = await ensureManager();
    if (!process.argv.includes('--no-browser')) openInterface(result.origin);
    console.log(result.status === 'existing' ? 'Interfaz del gestor existente abierta.' : 'Gestor iniciado y disponible.');
  } catch (error) {
    const safe = new Set(['FOREIGN_PORT', 'UNRESPONSIVE_PORT', 'INSTANCE_LOCKED', 'START_TIMEOUT', 'START_PENDING', 'LAUNCH_BUSY', 'LAUNCH_COORDINATION', 'PRIVATE_STORAGE_UNSAFE', 'BROWSER_UNAVAILABLE']);
    console.error(safe.has(error.code) ? error.message : 'No se pudo iniciar el gestor. Comprueba Node portable, los permisos y los registros de inicio.');
    process.exitCode = 1;
  }
}

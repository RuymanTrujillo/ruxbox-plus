// One request-body and session-aware JSON response contract, reused by
// all API routes. Invalid content, oversize bodies, stale sessions and
// interrupted clients keep the same fail-closed semantics.
export function createHttpTransport({maxBodyBytes,fault,assertCurrentSession,now,messages}){
  if(!Number.isInteger(maxBodyBytes)||maxBodyBytes<1||maxBodyBytes>8192||
    typeof fault!=='function'||typeof assertCurrentSession!=='function'||
    typeof now!=='function'||!messages||typeof messages.NOT_AUTHENTICATED!=='string')
      throw Error('INVALID_HTTP_TRANSPORT');
  async function bodyOf(req) {
    if (String(req.headers['content-type'] || '').split(';')[0].trim().toLowerCase() !== 'application/json') throw fault('BAD_REQUEST', 415);
    const length = Number(req.headers['content-length']);
    if (Number.isFinite(length) && length > maxBodyBytes) { req.resume(); throw fault('BODY_TOO_LARGE', 413); }
    return new Promise((resolve, reject) => {
      const chunks = []; let total = 0, rejected = false;
      req.on('data', chunk => {
        total += chunk.length;
        if (total > maxBodyBytes) { if (!rejected) reject(fault('BODY_TOO_LARGE', 413)); rejected = true; chunks.length = 0; }
        else if (!rejected) chunks.push(chunk);
      });
      req.on('end', () => {
        if (rejected) return;
        try { resolve(JSON.parse(Buffer.concat(chunks).toString('utf8'))); }
        catch { reject(fault('BAD_REQUEST')); }
      });
      req.on('aborted', () => reject(fault('BAD_REQUEST')));
      req.on('error', () => reject(fault('BAD_REQUEST')));
    });
  }
  function json(res, status, value) {
    const session = res.rearouterSession;
    if (session) {
      try {
        assertCurrentSession(session, res.rearouterAuthenticated && status < 400);
        res.setHeader('X-Rearouter-Session-Expires-At', new Date(session.expiresAt).toISOString());
        res.setHeader('X-Rearouter-Server-Time', now());
      } catch {
        if (status < 400) { status = 401; value = {error: {code: 'NOT_AUTHENTICATED', message: messages.NOT_AUTHENTICATED}}; }
      }
    }
    if (res.destroyed) return;
    res.writeHead(status, {'Content-Type': 'application/json; charset=utf-8'});
    res.end(JSON.stringify(value));
  }
  return {bodyOf,json};
}

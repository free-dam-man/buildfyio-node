'use strict';
// VLESS server: WebSocket + XHTTP(packet-up) transports, zero dependencies.
// - Listens on 0.0.0.0:$PORT (default 8080)
// - WS:      GET  /tk-rail                       (upgrade; plain GET -> 400)
// - XHTTP:   GET  /tk-rail/<sessionId>           (download stream)
//            POST /tk-rail/<sessionId>/<seq>     (upload packets, in order)
// - Other paths -> camouflage page / health endpoint
const http = require('http');
const net = require('net');
const crypto = require('crypto');

const PORT = parseInt(process.env.PORT || '3000', 10);
const UUID_STR = (process.env.NODE_UUID || '04edabca-a5e5-4f1d-b001-81e2f093076b').toLowerCase();
const UUID_BYTES = Buffer.from(UUID_STR.replace(/-/g, ''), 'hex');
const BASE_PATH = process.env.STREAM_PATH || '/tk-rail';
const SUB_TOKEN = process.env.SUB_TOKEN || '';
const NODE_HOST = process.env.NODE_HOST || '';
const TRANSPORT = (process.env.TRANSPORT || 'ws').toLowerCase();
const NODE_LABEL = process.env.NODE_LABEL || 'Dploy-01';
function buildSubscription() {
  const pathQ = encodeURIComponent(BASE_PATH);
  let uri;
  if (TRANSPORT === 'xhttp') {
    uri = 'vless://' + UUID_STR + '@' + NODE_HOST + ':443?encryption=none&security=tls&sni=' + NODE_HOST +
      '&alpn=h2&type=xhttp&host=' + NODE_HOST + '&path=' + pathQ + '&mode=packet-up#' + encodeURIComponent(NODE_LABEL);
  } else {
    uri = 'vless://' + UUID_STR + '@' + NODE_HOST + ':443?encryption=none&security=tls&sni=' + NODE_HOST +
      '&type=ws&host=' + NODE_HOST + '&path=' + pathQ + '#' + encodeURIComponent(NODE_LABEL);
  }
  return Buffer.from(uri, 'utf8').toString('base64');
}

const HOME = '<!doctype html><html><head><meta charset="utf-8"><title>Field Notes</title></head>' +
  '<body style="font-family:Georgia,serif;margin:40px auto;max-width:640px;line-height:1.6">' +
  '<h1>Field Notes</h1><p>A small journal of walks, weather and slow mornings.</p>' +
  '<p>New entries are posted when the season turns.</p></body></html>';

// ---------------- shared VLESS stream core ----------------
// A Session owns: the byte-stream parser for the VLESS request header,
// the outbound TCP socket, and a `sendDown(buf)` sink provided by the
// transport (WS frames or XHTTP GET response).
class Session {
  constructor(sendDown, onDead) {
    this.sendDown = sendDown;
    this.onDead = onDead;
    this.pending = Buffer.alloc(0);
    this.stage = 0; // 0 header, 1 relay
    this.tcp = null;
    this.respHeadSent = false;
    this.dead = false;
  }
  cleanup() {
    if (this.dead) return;
    this.dead = true;
    if (this.tcp) { try { this.tcp.destroy(); } catch (_) {} }
    if (this.onDead) { try { this.onDead(); } catch (_) {} }
  }
  feed(data) {
    if (this.dead || !data || !data.length) return;
    if (this.stage === 1) {
      if (this.tcp && !this.tcp.destroyed) {
        if (!this.tcp.write(data)) { /* basic backpressure ignored */ }
      }
      return;
    }
    this.pending = this.pending.length ? Buffer.concat([this.pending, data]) : data;
    this.tryHeader();
  }
  tryHeader() {
    const p = this.pending;
    if (p.length < 18) return;
    if (p[0] !== 0) return this.cleanup();
    if (!p.subarray(1, 17).equals(UUID_BYTES)) return this.cleanup();
    const m = p[17];
    const cmdOff = 18 + m;
    if (p.length < cmdOff + 4) return;
    if (p[cmdOff] !== 1) return this.cleanup(); // TCP only
    const port = p.readUInt16BE(cmdOff + 1);
    const atyp = p[cmdOff + 3];
    let idx = cmdOff + 4;
    let host = null;
    if (atyp === 1) {
      if (p.length < idx + 4) return;
      host = Array.from(p.subarray(idx, idx + 4)).join('.');
      idx += 4;
    } else if (atyp === 2) {
      if (p.length < idx + 1) return;
      const dl = p[idx];
      if (p.length < idx + 1 + dl) return;
      host = p.subarray(idx + 1, idx + 1 + dl).toString('utf8');
      idx += 1 + dl;
    } else if (atyp === 3) {
      if (p.length < idx + 16) return;
      const parts = [];
      for (let i = 0; i < 16; i += 2) parts.push(p.readUInt16BE(idx + i).toString(16));
      host = parts.join(':');
      idx += 16;
    } else return this.cleanup();
    const rest = p.subarray(idx);
    this.pending = Buffer.alloc(0);
    this.stage = 1;
    console.log('[sess] dialing ' + host + ':' + port + ' rest=' + rest.length + 'B');
    const tcp = net.connect({ host, port }, () => {
      console.log('[sess] tcp connected ' + host + ':' + port);
      if (rest.length) tcp.write(rest);
    });
    this.tcp = tcp;
    tcp.on('data', (chunk) => {
      console.log('[sess] tcp data ' + chunk.length + 'B head=' + !this.respHeadSent);
      if (!this.respHeadSent) {
        this.respHeadSent = true;
        chunk = Buffer.concat([Buffer.from([0, 0]), chunk]);
      }
      this.sendDown(chunk);
    });
    tcp.on('end', () => { console.log('[sess] tcp end'); this.cleanup(); });
    tcp.on('error', (e) => { console.log('[sess] tcp error ' + e.code + ' ' + e.message); this.cleanup(); });
    tcp.on('close', () => this.cleanup());
  }
}

// ---------------- WebSocket transport ----------------
function wsAccept(key) {
  return crypto.createHash('sha1')
    .update(key + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11')
    .digest('base64');
}
function encodeFrame(payload, opcode) {
  const len = payload.length;
  let head;
  if (len < 126) { head = Buffer.alloc(2); head[1] = len; }
  else if (len < 65536) { head = Buffer.alloc(4); head[1] = 126; head.writeUInt16BE(len, 2); }
  else { head = Buffer.alloc(10); head[1] = 127; head.writeBigUInt64BE(BigInt(len), 2); }
  head[0] = 0x80 | (opcode & 0x0f);
  return Buffer.concat([head, payload]);
}
class FrameParser {
  constructor(cb) { this.buf = Buffer.alloc(0); this.cb = cb; this.fragOp = -1; this.fragParts = []; }
  push(chunk) {
    this.buf = this.buf.length ? Buffer.concat([this.buf, chunk]) : chunk;
    for (;;) {
      if (this.buf.length < 2) return;
      const b0 = this.buf[0], b1 = this.buf[1];
      const fin = !!(b0 & 0x80), op = b0 & 0x0f, masked = !!(b1 & 0x80);
      let len = b1 & 0x7f, off = 2;
      if (len === 126) { if (this.buf.length < off + 2) return; len = this.buf.readUInt16BE(off); off += 2; }
      else if (len === 127) {
        if (this.buf.length < off + 8) return;
        const big = this.buf.readBigUInt64BE(off); off += 8;
        if (big > BigInt(64 * 1024 * 1024)) throw new Error('frame too large');
        len = Number(big);
      }
      let maskKey = null;
      if (masked) { if (this.buf.length < off + 4) return; maskKey = this.buf.subarray(off, off + 4); off += 4; }
      if (this.buf.length < off + len) return;
      let payload = Buffer.from(this.buf.subarray(off, off + len));
      this.buf = this.buf.subarray(off + len);
      if (maskKey) for (let i = 0; i < payload.length; i++) payload[i] ^= maskKey[i & 3];
      if (op === 0) {
        this.fragParts.push(payload);
        if (fin) { const full = Buffer.concat(this.fragParts); const o = this.fragOp; this.fragOp = -1; this.fragParts = []; this.cb(o, full); }
      } else if (op === 1 || op === 2) {
        if (fin) this.cb(op, payload); else { this.fragOp = op; this.fragParts = [payload]; }
      } else this.cb(op, payload);
    }
  }
}
function handleWs(socket, head) {
  if (head && head.length) socket.unshift(head);
  let chain = Promise.resolve();
  const wsWrite = (payload, opcode = 2) => {
    chain = chain.then(() => new Promise((resolve) => {
      if (socket.destroyed) return resolve();
      socket.write(encodeFrame(payload, opcode), resolve);
    }));
  };
  const session = new Session((buf) => wsWrite(buf, 2), () => { try { socket.destroy(); } catch (_) {} });
  const parser = new FrameParser((op, payload) => {
    if (op === 8) { session.cleanup(); return; }
    if (op === 9) { wsWrite(payload, 10); return; }
    if (op === 10) return;
    if (op === 1 || op === 2) session.feed(payload);
  });
  socket.on('data', (chunk) => { try { parser.push(chunk); } catch (_) { session.cleanup(); } });
  socket.on('error', () => session.cleanup());
  socket.on('close', () => session.cleanup());
  socket.on('end', () => session.cleanup());
}

// ---------------- XHTTP (packet-up) transport ----------------
const xSessions = new Map(); // sid -> entry
function getXSession(sid) {
  let e = xSessions.get(sid);
  if (e) return e;
  e = {
    sid,
    downRes: null,
    downBuf: [],
    downBufBytes: 0,
    nextSeq: 0,
    seqBuf: new Map(),
    lastSeen: Date.now(),
    session: null,
  };
  e.session = new Session((buf) => {
    if (e.downRes && !e.downRes.writableEnded) {
      e.downRes.write(buf);
    } else {
      e.downBuf.push(buf);
      e.downBufBytes += buf.length;
    }
  }, () => {
    // tcp side dead: close download stream, drop session shortly after
    if (e.downRes && !e.downRes.writableEnded) { try { e.downRes.end(); } catch (_) {} }
    setTimeout(() => xSessions.delete(sid), 5000).unref();
  });
  xSessions.set(sid, e);
  return e;
}
setInterval(() => {
  const now = Date.now();
  for (const [sid, e] of xSessions) {
    if (now - e.lastSeen > 5 * 60 * 1000) {
      e.session.cleanup();
      xSessions.delete(sid);
    }
  }
}, 60000).unref();

function handleXDownload(req, res, sid) {
  console.log('[xhttp] download open sid=' + sid.slice(0, 8));
  const e = getXSession(sid);
  e.lastSeen = Date.now();
  if (e.downRes && !e.downRes.writableEnded) { try { e.downRes.end(); } catch (_) {} }
  res.writeHead(200, {
    'Content-Type': 'application/octet-stream',
    'Cache-Control': 'no-store',
    'X-Accel-Buffering': 'no',
  });
  res.flushHeaders();
  e.downRes = res;
  if (e.downBuf.length) {
    for (const b of e.downBuf) res.write(b);
    e.downBuf = []; e.downBufBytes = 0;
  }
  res.on('close', () => {
    if (e.downRes === res) e.downRes = null;
    e.session.cleanup();
    xSessions.delete(sid);
  });
}
function handleXUpload(req, res, sid, seq) {
  const chunks = [];
  let size = 0;
  req.on('data', (c) => {
    size += c.length;
    if (size > 8 * 1024 * 1024) { req.destroy(); return; }
    chunks.push(c);
  });
  req.on('end', () => {
    const body = Buffer.concat(chunks);
    console.log('[xhttp] upload sid=' + sid.slice(0, 8) + ' seq=' + seq + ' bytes=' + body.length);
    const e = getXSession(sid);
    e.lastSeen = Date.now();
    if (seq === e.nextSeq) {
      e.session.feed(body);
      e.nextSeq++;
      while (e.seqBuf.has(e.nextSeq)) {
        e.session.feed(e.seqBuf.get(e.nextSeq));
        e.seqBuf.delete(e.nextSeq);
        e.nextSeq++;
      }
    } else if (seq > e.nextSeq) {
      e.seqBuf.set(seq, body);
    }
    res.writeHead(200, { 'Content-Type': 'text/plain', 'Cache-Control': 'no-store' });
    res.end('ok');
  });
  req.on('error', () => { try { res.writeHead(400); res.end(); } catch (_) {} });
}

// ---------------- HTTP server ----------------
const server = http.createServer((req, res) => {
  const rawUrl = req.url || '/';
  const path = rawUrl.split('?')[0];
  console.log('[http] ' + req.method + ' ' + path.slice(0, 60));
  if (path === BASE_PATH) {
    if (req.method === 'GET') {
      res.writeHead(400, { 'Content-Type': 'text/plain' });
      res.end('Bad Request');
      return;
    }
    res.writeHead(405); res.end(); return;
  }
  if (path.startsWith(BASE_PATH + '/')) {
    const parts = path.slice(BASE_PATH.length + 1).split('/');
    const sid = decodeURIComponent(parts[0] || '');
    if (!sid) { res.writeHead(404); res.end(); return; }
    if (req.method === 'GET' && parts.length === 1) return handleXDownload(req, res, sid);
    if (req.method === 'POST' && parts.length === 2) {
      const seq = parseInt(parts[1], 10);
      if (Number.isNaN(seq)) { res.writeHead(404); res.end(); return; }
      return handleXUpload(req, res, sid, seq);
    }
    res.writeHead(404); res.end(); return;
  }
  if (path === '/sub') {
    const q = new URLSearchParams(rawUrl.split('?')[1] || '');
    const t = q.get('token') || '';
    const a = Buffer.from(t), b = Buffer.from(SUB_TOKEN);
    if (!SUB_TOKEN || a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
      res.writeHead(404, { 'Content-Type': 'text/plain' }); res.end('not found'); return;
    }
    res.writeHead(200, { 'Content-Type': 'text/plain', 'Cache-Control': 'no-store' });
    res.end(buildSubscription());
    return;
  }
  if (path === '/health') {
    res.writeHead(200, { 'Content-Type': 'text/plain' });
    res.end('ok');
    return;
  }
  res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
  res.end(HOME);
});

server.on('upgrade', (req, socket, head) => {
  const path = (req.url || '').split('?')[0];
  const key = req.headers['sec-websocket-key'];
  if (path !== BASE_PATH || !key) {
    socket.write('HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n');
    socket.destroy();
    return;
  }
  socket.write(
    'HTTP/1.1 101 Switching Protocols\r\n' +
    'Upgrade: websocket\r\n' +
    'Connection: Upgrade\r\n' +
    'Sec-WebSocket-Accept: ' + wsAccept(key) + '\r\n\r\n'
  );
  socket.setNoDelay(true);
  handleWs(socket, head);
});

server.listen(PORT, '0.0.0.0', () => {
  console.log('listening on ' + PORT);
});

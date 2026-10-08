// KM Remote – Signaling-Server.
// Vermittelt nur den WebRTC-Verbindungsaufbau (ID-Verzeichnis + Nachrichten-Relay).
// Bildschirm, Eingaben und Dateien laufen Ende-zu-Ende verschlüsselt direkt zwischen den
// Geräten (WebRTC/DTLS) – bzw. über TURN, falls kein direkter Weg möglich ist.
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { WebSocketServer } = require('ws');

const PORT = process.env.PORT || 4400;
const DB = process.env.DATA_FILE || path.join(__dirname, 'ids.json');

let ids = {};
try { ids = JSON.parse(fs.readFileSync(DB, 'utf8')); } catch {}
const save = () => { try { fs.writeFileSync(DB, JSON.stringify(ids)); } catch {} };

// ICE-Server, die an die Clients ausgeliefert werden. Für Verbindungen hinter strengen
// NATs/Firewalls unbedingt einen TURN-Server eintragen (z. B. coturn):
//   TURN_URL=turn:turn.example.com:3478  TURN_USER=...  TURN_PASS=...
function iceServers() {
  const list = [{ urls: ['stun:stun.l.google.com:19302', 'stun:stun.cloudflare.com:3478'] }];
  if (process.env.TURN_URL) {
    list.push({ urls: process.env.TURN_URL.split(','), username: process.env.TURN_USER, credential: process.env.TURN_PASS });
  }
  return list;
}

const clients = new Map(); // id -> ws

const server = http.createServer((req, res) => {
  if (req.url === '/health') { res.writeHead(200); return res.end('ok'); }
  if (req.url === '/stats') { res.writeHead(200, { 'content-type': 'application/json' }); return res.end(JSON.stringify({ online: clients.size })); }
  res.writeHead(404); res.end();
});
const wss = new WebSocketServer({ server, maxPayload: 256 * 1024 });

function newId() {
  for (;;) {
    const id = String(100000000 + crypto.randomInt(900000000));
    if (!ids[id] && !clients.has(id)) return id;
  }
}
const send = (ws, o) => { if (ws.readyState === 1) ws.send(JSON.stringify(o)); };

wss.on('connection', (ws) => {
  ws.alive = true;
  ws.on('pong', () => { ws.alive = true; });
  ws.bucket = 60; // einfaches Rate-Limit (Token-Bucket)
  const refill = setInterval(() => { ws.bucket = Math.min(60, ws.bucket + 30); }, 1000);

  ws.on('message', (raw) => {
    if (--ws.bucket < 0) return;
    let m; try { m = JSON.parse(raw); } catch { return; }

    if (m.t === 'hello' && !ws.id) {
      if (m.ephemeral) {
        ws.id = 'v' + crypto.randomBytes(5).toString('hex');
        ws.ephemeral = true;
        clients.set(ws.id, ws);
        return send(ws, { t: 'welcome', id: ws.id, ice: iceServers() });
      }
      let id = typeof m.id === 'string' && /^\d{9}$/.test(m.id) ? m.id : null;
      let token = typeof m.token === 'string' ? m.token : '';
      if (id && ids[id] && ids[id] !== token) id = null; // ID gehört einem anderen Gerät
      if (!id) { id = newId(); token = crypto.randomBytes(24).toString('hex'); ids[id] = token; save(); }
      else if (!ids[id]) { token = crypto.randomBytes(24).toString('hex'); ids[id] = token; save(); }
      const old = clients.get(id);
      if (old && old !== ws) { try { old.close(); } catch {} }
      ws.id = id;
      clients.set(id, ws);
      return send(ws, { t: 'welcome', id, token, ice: iceServers() });
    }
    if (!ws.id) return;

    if (m.t === 'sig' && typeof m.to === 'string') {
      const target = clients.get(m.to);
      if (!target) return send(ws, { t: 'err', code: 'offline', to: m.to });
      return send(target, { t: 'sig', from: ws.id, data: m.data });
    }
    if (m.t === 'query') return send(ws, { t: 'presence', id: m.id, online: clients.has(m.id) });
    if (m.t === 'ping') return send(ws, { t: 'pong' });
  });

  ws.on('close', () => {
    clearInterval(refill);
    if (ws.id && clients.get(ws.id) === ws) clients.delete(ws.id);
  });
  ws.on('error', () => {});
});

setInterval(() => {
  for (const ws of wss.clients) {
    if (!ws.alive) { ws.terminate(); continue; }
    ws.alive = false; ws.ping();
  }
}, 30000);

server.listen(PORT, () => console.log(`[KM Remote] Signaling-Server läuft auf Port ${PORT}`));

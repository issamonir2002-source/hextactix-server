// Hex Tactics online server: friend codes, who's online, invites, and passing match moves between two players.
// Plain Node.js (no packages). Run: node server.js   (port from $PORT, default 8080)
// Players connect with a WebSocket and send JSON messages:
//   hello {v, id, secret, name}   who {ids}   name {name}   invite {to}   cancel {to}   accept {from}
//   decline {from}   leave   relay {d}   ping
// The server answers:
//   welcome   error {msg}   who {online: {id: {name, busy}}}   invite {from, name}   cancelled {from}
//   declined {from, name}   paired {host, peer, name}   peer_left   relay {d}   pong
// Nothing is saved: friend lists live in each game; the server only knows who is connected right now.

const http = require("http");
const crypto = require("crypto");

const PORT = Number(process.env.PORT) || 8080;
const MAX_MESSAGE = 1 << 20;
const clients = new Map();   // id -> client {sock, id, secret, name, v, peer, invited:Set}

const server = http.createServer((req, res) => {
  res.writeHead(200, {"content-type": "text/plain"});
  res.end(`Hex Tactics server is running. ${clients.size} player(s) online.\n`);
});

server.on("upgrade", (req, sock) => {
  const key = req.headers["sec-websocket-key"];
  if (!key || (req.headers.upgrade || "").toLowerCase() !== "websocket") {
    sock.destroy();
    return;
  }
  const accept = crypto.createHash("sha1").update(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").digest("base64");
  sock.write("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" +
    `Sec-WebSocket-Accept: ${accept}\r\n\r\n`);
  sock.setNoDelay(true);
  const conn = {sock, client: null, buf: Buffer.alloc(0), frags: []};
  sock.on("data", (d) => onData(conn, d));
  sock.on("close", () => onClose(conn));
  sock.on("error", () => sock.destroy());
});

// ---------------------------------------------------------------- WebSocket frames
function onData(conn, data) {
  conn.buf = Buffer.concat([conn.buf, data]);
  while (conn.buf.length >= 2) {
    const b0 = conn.buf[0], b1 = conn.buf[1];
    const fin = (b0 & 0x80) !== 0, op = b0 & 0x0f, masked = (b1 & 0x80) !== 0;
    let len = b1 & 0x7f, at = 2;
    if (len === 126) {
      if (conn.buf.length < 4) return;
      len = conn.buf.readUInt16BE(2); at = 4;
    } else if (len === 127) {
      if (conn.buf.length < 10) return;
      len = Number(conn.buf.readBigUInt64BE(2)); at = 10;
    }
    if (len > MAX_MESSAGE) { conn.sock.destroy(); return; }
    const need = at + (masked ? 4 : 0) + len;
    if (conn.buf.length < need) return;
    let payload = conn.buf.subarray(at + (masked ? 4 : 0), need);
    if (masked) {
      const mask = conn.buf.subarray(at, at + 4);
      payload = Buffer.from(payload);
      for (let i = 0; i < payload.length; i++) payload[i] ^= mask[i & 3];
    }
    conn.buf = conn.buf.subarray(need);
    if (op === 0x8) { conn.sock.end(); return; }                 // close
    if (op === 0x9) { sendFrame(conn.sock, 0xa, payload); continue; }  // ping -> pong
    if (op === 0xa) continue;
    if (op === 0x1 || op === 0x2 || op === 0x0) {
      conn.frags.push(payload);
      if (!fin) continue;
      const text = Buffer.concat(conn.frags).toString("utf8");
      conn.frags = [];
      let msg;
      try { msg = JSON.parse(text); } catch { continue; }
      if (msg && typeof msg === "object") onMessage(conn, msg);
    }
  }
}

function sendFrame(sock, op, payload) {
  const len = payload.length;
  let head;
  if (len < 126) head = Buffer.from([0x80 | op, len]);
  else if (len < 65536) { head = Buffer.alloc(4); head[0] = 0x80 | op; head[1] = 126; head.writeUInt16BE(len, 2); }
  else { head = Buffer.alloc(10); head[0] = 0x80 | op; head[1] = 127; head.writeBigUInt64BE(BigInt(len), 2); }
  if (!sock.destroyed) sock.write(Buffer.concat([head, payload]));
}

function send(client, msg) {
  if (client) sendFrame(client.sock, 0x1, Buffer.from(JSON.stringify(msg), "utf8"));
}

// ---------------------------------------------------------------- players
const ID_RE = /^[2-9A-HJ-NP-Z]{6}$/;

function cleanName(n) {
  return String(n || "").replace(/[\x00-\x1f]/g, "").trim().slice(0, 16) || "Player";
}

function onMessage(conn, msg) {
  const me = conn.client;
  if (msg.t === "hello") {
    const id = String(msg.id || ""), secret = String(msg.secret || "");
    if (!ID_RE.test(id) || secret.length < 8) return send({sock: conn.sock}, {t: "error", msg: "Bad friend code."});
    const old = clients.get(id);
    if (old && old.secret !== secret) return send({sock: conn.sock}, {t: "error", msg: "That friend code is in use."});
    if (old) {   // the same player reconnecting: the old connection is dropped
      old.sock.removeAllListeners("close");
      old.sock.destroy();
      unpair(old);
    }
    const client = {sock: conn.sock, id, secret, name: cleanName(msg.name), v: String(msg.v || ""), peer: null,
      invited: new Set()};
    conn.client = client;
    clients.set(id, client);
    return send(client, {t: "welcome"});
  }
  if (!me || clients.get(me.id) !== me) return;
  switch (msg.t) {
    case "ping":
      return send(me, {t: "pong"});
    case "name":
      me.name = cleanName(msg.name);
      return;
    case "who": {
      const online = {};
      for (const id of Array.isArray(msg.ids) ? msg.ids.slice(0, 200) : []) {
        const c = clients.get(String(id));
        if (c) online[c.id] = {name: c.name, busy: c.peer !== null};
      }
      return send(me, {t: "who", online});
    }
    case "invite": {
      const to = clients.get(String(msg.to));
      if (!to) return send(me, {t: "error", msg: "Your friend isn't online."});
      if (to === me) return send(me, {t: "error", msg: "That's your own code."});
      if (to.peer) return send(me, {t: "error", msg: `${to.name} is in a match.`});
      me.invited.add(to.id);
      return send(to, {t: "invite", from: me.id, name: me.name});
    }
    case "cancel": {
      const to = clients.get(String(msg.to));
      me.invited.delete(String(msg.to));
      return send(to, {t: "cancelled", from: me.id});
    }
    case "decline": {
      const from = clients.get(String(msg.from));
      if (from) from.invited.delete(me.id);
      return send(from, {t: "declined", from: me.id, name: me.name});
    }
    case "accept": {
      const from = clients.get(String(msg.from));
      if (!from || !from.invited.has(me.id)) return send(me, {t: "error", msg: "That invite is no longer open."});
      if (from.peer || me.peer) return send(me, {t: "error", msg: "One of you is already in a match."});
      if (from.v !== me.v) {
        send(from, {t: "error", msg: `${me.name} has a different version of the game. Both need the same copy.`});
        return send(me, {t: "error", msg: `${from.name} has a different version of the game. Both need the same copy.`});
      }
      from.invited.clear();
      me.invited.clear();
      from.peer = me;
      me.peer = from;
      send(from, {t: "paired", host: true, peer: me.id, name: me.name});
      return send(me, {t: "paired", host: false, peer: from.id, name: from.name});
    }
    case "leave":
      return unpair(me);
    case "relay":
      return send(me.peer, {t: "relay", d: msg.d});
  }
}

function unpair(client) {
  const peer = client.peer;
  client.peer = null;
  if (peer && peer.peer === client) {
    peer.peer = null;
    send(peer, {t: "peer_left"});
  }
}

function onClose(conn) {
  const c = conn.client;
  if (c && clients.get(c.id) === c) {
    clients.delete(c.id);
    unpair(c);
  }
}

server.listen(PORT, () => console.log(`Hex Tactics server listening on port ${PORT}`));

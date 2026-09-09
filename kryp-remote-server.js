/* KrypCoin remote realtime relay server
 * No npm dependencies. Node.js 18+.
 * Set ADMIN_TOKEN and CUSTOMER_TOKEN before starting.
 */
'use strict';

const http = require('http');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const PORT = Number(process.env.PORT || 8080);
const ADMIN_TOKEN = process.env.ADMIN_TOKEN || 'CHANGE_ME_ADMIN_TOKEN';
const CUSTOMER_TOKEN = process.env.CUSTOMER_TOKEN || 'CHANGE_ME_CUSTOMER_TOKEN';
const DATA_FILE = process.env.EVENT_FILE || path.join(__dirname, 'kryp-events.json');
const MAX_EVENTS = Number(process.env.MAX_EVENTS || 20000);

let cursor = 0;
let events = [];

try {
  const saved = JSON.parse(fs.readFileSync(DATA_FILE, 'utf8'));
  cursor = Number(saved.cursor || 0);
  events = Array.isArray(saved.events) ? saved.events : [];
} catch (_) {}

const clients = new Set();

function tokenFor(role) {
  return role === 'admin' ? ADMIN_TOKEN : CUSTOMER_TOKEN;
}

function validRole(role) {
  return role === 'admin' || role === 'customer';
}

function authorized(role, token) {
  return validRole(role) &&
    token &&
    token === tokenFor(role) &&
    !String(token).startsWith('CHANGE_ME_');
}

function save() {
  try {
    const tmp = DATA_FILE + '.tmp';
    fs.writeFileSync(
      tmp,
      JSON.stringify({ cursor, events }, null, 2)
    );
    fs.renameSync(tmp, DATA_FILE);
  } catch (e) {
    console.error('event save failed:', e.message);
  }
}

function recipientRoles(sourceRole) {
  return sourceRole === 'admin'
    ? ['customer']
    : ['admin'];
}

function visibleToRole(e, role) {
  return Array.isArray(e.toRoles) &&
    e.toRoles.includes(role);
}

function publish(sourceRole, data) {
  const id = String(
    data && data.eventId ||
    'evt-' + crypto.randomUUID()
  );

  cursor += 1;

  const event = {
    eventId: id,
    cursor,
    sourceRole,
    createdAt: new Date().toISOString(),
    data: Object.assign({}, data, {
      eventId: id
    })
  };

  event.toRoles = recipientRoles(sourceRole);

  events.push(event);

  if (events.length > MAX_EVENTS) {
    events = events.slice(-MAX_EVENTS);
  }

  save();

  for (const c of clients) {
    if (!c.auth || !visibleToRole(event, c.role)) {
      continue;
    }

    sendWs(c.socket, {
      type: 'event',
      data: event.data,
      cursor: event.cursor
    });
  }

  return event;
}

function parseWsFrames(buffer) {
  const frames = [];
  let off = 0;

  while (off + 2 <= buffer.length) {
    const b1 = buffer[off];
    const b2 = buffer[off + 1];

    const opcode = b1 & 0x0f;
    const masked = !!(b2 & 0x80);

    let len = b2 & 0x7f;
    let head = 2;

    if (len === 126) {
      if (off + 4 > buffer.length) break;

      len = buffer.readUInt16BE(off + 2);
      head = 4;
    } else if (len === 127) {
      if (off + 10 > buffer.length) break;

      const hi = buffer.readUInt32BE(off + 2);
      const lo = buffer.readUInt32BE(off + 6);

      if (hi !== 0) {
        throw new Error('frame too large');
      }

      len = lo;
      head = 10;
    }

    if (!masked) {
      throw new Error('client frame not masked');
    }

    if (off + head + 4 + len > buffer.length) {
      break;
    }

    const key = buffer.subarray(
      off + head,
      off + head + 4
    );

    const start = off + head + 4;

    const payload = Buffer.alloc(len);

    for (let i = 0; i < len; i++) {
      payload[i] =
        buffer[start + i] ^
        key[i % 4];
    }

    frames.push({
      opcode,
      payload
    });

    off = start + len;
  }

  return {
    frames,
    rest: buffer.subarray(off)
  };
}

function sendWs(socket, obj) {
  const payload = Buffer.from(
    JSON.stringify(obj)
  );

  let header;

  if (payload.length < 126) {
    header = Buffer.from([
      0x81,
      payload.length
    ]);
  } else if (payload.length < 65536) {
    header = Buffer.alloc(4);
    header[0] = 0x81;
    header[1] = 126;
    header.writeUInt16BE(
      payload.length,
      2
    );
  } else {
    header = Buffer.alloc(10);
    header[0] = 0x81;
    header[1] = 127;
    header.writeUInt32BE(0, 2);
    header.writeUInt32BE(
      payload.length,
      6
    );
  }

  socket.write(
    Buffer.concat([
      header,
      payload
    ])
  );
}

function sendClose(socket) {
  try {
    socket.write(
      Buffer.from([0x88, 0])
    );
    socket.end();
  } catch (_) {}
}

function httpJson(res, status, obj) {
  const body = JSON.stringify(obj);

  res.writeHead(status, {
    'Content-Type': 'application/json',
    'Cache-Control': 'no-store',
    'Access-Control-Allow-Origin': '*'
  });

  res.end(body);
}

function readJson(req, cb) {
  let body = '';

  req.on('data', d => {
    body += d;

    if (body.length > 2e6) {
      req.destroy();
    }
  });

  req.on('end', () => {
    try {
      cb(JSON.parse(body || '{}'));
    } catch (e) {
      cb(null);
    }
  });
}

const server = http.createServer(
  (req, res) => {

    if (req.method === 'OPTIONS') {
      res.writeHead(204, {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Headers':
          'Content-Type,X-Kryp-Token',
        'Access-Control-Allow-Methods':
          'GET,POST,OPTIONS'
      });

      return res.end();
    }

    const u = new URL(
      req.url,
      'http://localhost'
    );

    if (u.pathname === '/health') {
      return httpJson(
        res,
        200,
        {
          ok: true,
          cursor,
          clients: clients.size,
          events: events.length
        }
      );
    }

    if (
      u.pathname === '/api/events' &&
      req.method === 'GET'
    ) {
      const role =
        u.searchParams.get('role') || '';

      const token =
        req.headers['x-kryp-token'] || '';

      if (!authorized(role, token)) {
        return httpJson(
          res,
          401,
          { error: 'unauthorized' }
        );
      }

      const after = Number(
        u.searchParams.get('after') || 0
      );

      const matching = events
        .filter(e =>
          e.cursor > after &&
          visibleToRole(e, role)
        )
        .slice(-1000);

      const out =
        matching.map(e => e.data);

      const next =
        matching.length
          ? matching[matching.length - 1].cursor
          : after;

      return httpJson(
        res,
        200,
        {
          events: out,
          nextCursor: next
        }
      );
    }

    if (
      u.pathname === '/api/events' &&
      req.method === 'POST'
    ) {
      readJson(req, data => {

        const role =
          data && data.role;

        const token =
          req.headers['x-kryp-token'] ||
          (data && data.token);

        if (!authorized(role, token)) {
          return httpJson(
            res,
            401,
            { error: 'unauthorized' }
          );
        }

        const event =
          data.event ||
          data.data;

        if (
          !event ||
          typeof event !== 'object'
        ) {
          return httpJson(
            res,
            400,
            { error: 'invalid event' }
          );
        }

        const published =
          publish(role, event);

        return httpJson(
          res,
          201,
          {
            ok: true,
            eventId: published.eventId,
            cursor: published.cursor
          }
        );
      });

      return;
    }

    res.writeHead(404);
    res.end('Not found');
  }
);

server.on(
  'upgrade',
  (req, socket) => {

    const u = new URL(
      req.url,
      'http://localhost'
    );

    if (u.pathname !== '/ws') {
      socket.destroy();
      return;
    }

    const role =
      u.searchParams.get('role') || '';

    const token =
      u.searchParams.get('token') || '';

    if (!authorized(role, token)) {
      socket.write(
        'HTTP/1.1 401 Unauthorized\r\n\r\n'
      );

      socket.destroy();
      return;
    }

    const key =
      req.headers['sec-websocket-key'];

    if (!key) {
      socket.destroy();
      return;
    }

    const accept =
      crypto
        .createHash('sha1')
        .update(
          key +
          '258EAFA5-E914-47DA-95CA-C5AB0DC85B11'
        )
        .digest('base64');

    socket.write(
      'HTTP/1.1 101 Switching Protocols\r\n' +
      'Upgrade: websocket\r\n' +
      'Connection: Upgrade\r\n' +
      'Sec-WebSocket-Accept: ' +
      accept +
      '\r\n\r\n'
    );

    const client = {
      socket,
      role,
      auth: true,
      buffer: Buffer.alloc(0)
    };

    clients.add(client);

    sendWs(socket, {
      type: 'hello',
      cursor
    });

    socket.on('data', chunk => {

      try {
        client.buffer =
          Buffer.concat([
            client.buffer,
            chunk
          ]);

        const parsed =
          parseWsFrames(
            client.buffer
          );

        client.buffer =
          parsed.rest;

        for (const f of parsed.frames) {

          if (f.opcode === 8) {
            sendClose(socket);
            clients.delete(client);
            return;
          }

          if (f.opcode === 9) {
            const pong =
              Buffer.from([
                0x8a,
                f.payload.length
              ]);

            socket.write(
              Buffer.concat([
                pong,
                f.payload
              ])
            );

            continue;
          }

          if (f.opcode !== 1) {
            continue;
          }

          const msg =
            JSON.parse(
              f.payload.toString('utf8')
            );

          if (
            msg.type === 'event' &&
            msg.data &&
            typeof msg.data === 'object'
          ) {
            publish(
              role,
              msg.data
            );
          }
        }

      } catch (e) {
        console.error(
          'ws frame error:',
          e.message
        );

        sendClose(socket);
        clients.delete(client);
      }
    });

    socket.on(
      'close',
      () => clients.delete(client)
    );

    socket.on(
      'error',
      () => clients.delete(client)
    );
  }
);

server.listen(
  PORT,
  () => console.log(
    `Kryp remote server listening on :${PORT}`
  )
);

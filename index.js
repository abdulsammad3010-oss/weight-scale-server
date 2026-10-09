/**
 * WebSocket Server for ESP32 Weight Scale Logger
 * Only stores account/device metadata — NOT weight history
 */

const WebSocket = require('ws');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');

const JWT_SECRET = process.env.JWT_SECRET || 'change-me-in-production-xyz-123';
const PORT = process.env.PORT || 8080;

// In-memory stores
const customers = new Map();
const devices = new Map();

// Initialize demo accounts
(async () => {
  const custHash = await bcrypt.hash('demo123', 10);
  customers.set('abc123', {
    id: 'cust_001',
    name: 'ABC Company',
    passwordHash: custHash,
    deviceIds: ['WT001']
  });

  const devHash = await bcrypt.hash('my-secret-WT001-abc123-change-this', 10);
  devices.set('WT001', {
    customerId: 'cust_001',
    secretHash: devHash,
    ws: null,
    lastSeen: 0
  });

  console.log('[Init] Customer: abc123 / demo123');
  console.log('[Init] Device:   WT001');
})();

const wss = new WebSocket.Server({ port: PORT });
console.log(`[Server] WebSocket listening on port ${PORT}`);

wss.on('connection', (ws) => {
  ws.isAlive = true;

  ws.on('pong', () => { ws.isAlive = true; });

  ws.on('message', async (data) => {
    let msg;
    try { msg = JSON.parse(data); } catch { return; }

    switch (msg.type) {
      case 'device_auth':     handleDeviceAuth(ws, msg); break;
      case 'customer_auth':   await handleCustomerAuth(ws, msg); break;
      case 'weight':          handleWeight(ws, msg); break;
      case 'history_request': handleHistoryRequest(ws, msg); break;
      case 'history_start':
      case 'history_chunk':
      case 'history_end':     handleHistoryResponse(ws, msg); break;
      case 'ping':            ws.send(JSON.stringify({ type: 'pong' })); break;
    }
  });

  ws.on('close', () => {
    if (ws.deviceId && devices.has(ws.deviceId)) {
      const dev = devices.get(ws.deviceId);
      if (dev.ws === ws) {
        dev.ws = null;
        notifyDeviceStatus(ws.deviceId, 'offline');
      }
    }
  });

  ws.on('error', (err) => console.log('[WS] Error:', err.message));
});

setInterval(() => {
  wss.clients.forEach(ws => {
    if (!ws.isAlive) return ws.terminate();
    ws.isAlive = false;
    ws.ping();
  });
}, 30000);

function handleDeviceAuth(ws, msg) {
  const { device_id, secret } = msg;
  const dev = devices.get(device_id);

  if (!dev) {
    ws.send(JSON.stringify({ type: 'auth_error', message: 'Unknown device' }));
    return ws.close();
  }

  bcrypt.compare(secret, dev.secretHash).then(valid => {
    if (!valid) {
      ws.send(JSON.stringify({ type: 'auth_error', message: 'Invalid secret' }));
      return ws.close();
    }

    dev.ws = ws;
    dev.lastSeen = Date.now();
    ws.deviceId = device_id;

    console.log(`[Device] ${device_id} authenticated`);
    ws.send(JSON.stringify({ type: 'auth_ok', device_id }));
    notifyDeviceStatus(device_id, 'online');
  });
}

async function handleCustomerAuth(ws, msg) {
  const { username, password } = msg;
  const customer = customers.get(username);

  if (!customer) {
    ws.send(JSON.stringify({ type: 'auth_error', message: 'Invalid credentials' }));
    return;
  }

  const valid = await bcrypt.compare(password, customer.passwordHash);
  if (!valid) {
    ws.send(JSON.stringify({ type: 'auth_error', message: 'Invalid credentials' }));
    return;
  }

  const token = jwt.sign(
    { customerId: customer.id, username },
    JWT_SECRET,
    { expiresIn: '24h' }
  );

  ws.customerId = customer.id;
  ws.username = username;

  console.log(`[Customer] ${username} logged in`);
  ws.send(JSON.stringify({
    type: 'auth_ok',
    token,
    customer: { name: customer.name, username, deviceIds: customer.deviceIds }
  }));

  customer.deviceIds.forEach(did => {
    const d = devices.get(did);
    if (d) {
      ws.send(JSON.stringify({
        type: 'device_status',
        device_id: did,
        status: d.ws ? 'online' : 'offline',
        last_seen: d.lastSeen
      }));
    }
  });
}

function handleWeight(ws, msg) {
  if (!ws.deviceId) return;
  const dev = devices.get(ws.deviceId);
  if (dev) dev.lastSeen = Date.now();

  const customer = Array.from(customers.values())
    .find(c => c.deviceIds.includes(ws.deviceId));

  if (customer) {
    wss.clients.forEach(client => {
      if (client.customerId === customer.id && client.readyState === WebSocket.OPEN) {
        client.send(JSON.stringify(msg));
      }
    });
  }
}

function handleHistoryRequest(ws, msg) {
  if (!ws.customerId) {
    return ws.send(JSON.stringify({ type: 'error', message: 'Not authenticated' }));
  }

  const { device_id, from, to, request_id } = msg;

  const customer = Array.from(customers.values())
    .find(c => c.id === ws.customerId);

  if (!customer || !customer.deviceIds.includes(device_id)) {
    return ws.send(JSON.stringify({ type: 'error', message: 'Unauthorized device' }));
  }

  const dev = devices.get(device_id);
  if (!dev || !dev.ws) {
    return ws.send(JSON.stringify({
      type: 'history_error',
      request_id,
      message: 'Device offline'
    }));
  }

  ws.activeRequests = ws.activeRequests || {};
  ws.activeRequests[request_id] = { device_id, customerId: ws.customerId };

  dev.ws.send(JSON.stringify({
    type: 'history_request',
    device_id, from, to, request_id
  }));
}

function handleHistoryResponse(ws, msg) {
  if (!ws.deviceId) return;
  const requestId = msg.request_id;

  wss.clients.forEach(client => {
    if (client.activeRequests && client.activeRequests[requestId]) {
      client.send(JSON.stringify(msg));
      if (msg.type === 'history_end') {
        delete client.activeRequests[requestId];
      }
    }
  });
}

function notifyDeviceStatus(deviceId, status) {
  const dev = devices.get(deviceId);
  if (!dev) return;

  wss.clients.forEach(client => {
    if (client.customerId === dev.customerId) {
      client.send(JSON.stringify({
        type: 'device_status',
        device_id: deviceId,
        status,
        last_seen: dev.lastSeen
      }));
    }
  });
}
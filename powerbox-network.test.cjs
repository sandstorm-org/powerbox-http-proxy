const {test} = require('node:test');
const assert = require('node:assert/strict');
const vm = require('node:vm');
const fs = require('node:fs');
const {webcrypto} = require('node:crypto');

function helper() {
  const listeners = new Set();
  const calls = [];
  const messages = [];
  const window = {
    parent: {postMessage: message => messages.push(message)},
    addEventListener: (_, handler) => listeners.add(handler),
    removeEventListener: (_, handler) => listeners.delete(handler),
  };
  let failClaim = false;
  vm.runInNewContext(fs.readFileSync('powerbox-network.js', 'utf8'), {
    window, crypto: webcrypto,
    fetch: async (path, options) => {
      calls.push({path, ...options});
      return {
        ok: !(failClaim && options.method === 'POST'),
        text: async () => 'Claim failed',
        json: async () => ({configured: false, valid: false, descriptor: 'query'}),
      };
    },
  });
  return {
    api: window.powerboxNetwork, calls, messages, listeners,
    failClaim: () => { failClaim = true; },
    reply(data, source = window.parent) {
      for (const handler of listeners) handler({data, source});
    },
  };
}

const tick = () => new Promise(resolve => setImmediate(resolve));

test('connect accepts only the matching parent reply and sends only the token', async () => {
  const h = helper();
  const pending = h.api.connect('App network');
  await tick();
  const request = h.messages[0].powerboxRequest;
  assert.equal(request.query[0], 'query');
  assert.equal(request.saveLabel.defaultText, 'App network');
  h.reply({rpcId: request.rpcId, token: 'forged'}, {});
  h.reply({rpcId: 'wrong', token: 'stale'});
  assert.equal(h.calls.length, 1);
  h.reply({rpcId: request.rpcId, token: 'claim'});
  await pending;
  assert.equal(h.listeners.size, 0);
  assert.equal(h.calls[1].path, '/_sandstorm/network');
  assert.equal(h.calls[1].method, 'POST');
  assert.equal(h.calls[1].headers['X-Sandstorm-App-Network'], '1');
  assert.deepEqual(JSON.parse(h.calls[1].body), {token: 'claim'});
  await h.api.disconnect();
  assert.equal(h.calls[2].method, 'DELETE');
});

test('cancellation cleans up and allows another selection', async () => {
  const h = helper();
  const pending = h.api.connect();
  const rejected = assert.rejects(pending, /canceled/);
  await tick();
  await assert.rejects(h.api.connect(), /already in progress/);
  h.reply({rpcId: h.messages[0].powerboxRequest.rpcId});
  await rejected;
  assert.equal(h.listeners.size, 0);
  assert.equal(h.calls.length, 1);
  const retry = h.api.connect();
  await tick();
  h.reply({rpcId: h.messages[1].powerboxRequest.rpcId, token: 'claim'});
  await retry;
});

test('claim errors reach the UI and release the pending selection', async () => {
  const h = helper();
  h.failClaim();
  const pending = h.api.connect();
  const rejected = assert.rejects(pending, /Claim failed/);
  await tick();
  h.reply({rpcId: h.messages[0].powerboxRequest.rpcId, token: 'claim'});
  await rejected;
  assert.equal(h.listeners.size, 0);
});

test('per-site helper ignores network replies and removes disconnected listeners', () => {
  const listeners = new Set();
  const sent = [];
  let socket;
  const window = {
    location: {protocol: 'https:', host: 'grain.test'},
    parent: {postMessage() {}},
    addEventListener: (_, handler) => listeners.add(handler),
    removeEventListener: (_, handler) => listeners.delete(handler),
  };
  vm.runInNewContext(fs.readFileSync('powerbox-http-proxy.js', 'utf8'), {
    window, console: {log() {}}, setTimeout() {},
    WebSocket: class {
      constructor() { socket = this; }
      send(message) { sent.push(JSON.parse(message)); }
    },
  });
  socket.onmessage({data: JSON.stringify({powerboxRequest: {rpcId: 0}})});
  for (const listener of listeners) {
    listener({source: window.parent, data: {rpcId: 'powerbox-network-abc', token: 'network'}});
  }
  assert.equal(sent.length, 0);
  for (const listener of listeners) {
    listener({source: window.parent, data: {rpcId: 0, token: 'site'}});
  }
  assert.deepEqual(sent, [{rpcId: 0, token: 'site'}]);
  socket.onclose();
  assert.equal(listeners.size, 0);
});

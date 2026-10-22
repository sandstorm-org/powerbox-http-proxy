// Optional helper for applications that offer an IpNetwork connection.
// Calls the application backend, which must authorize requests and supply the
// trusted session ID before forwarding claims to the proxy. See README.md.
(() => {
  let connecting = false;

  async function request(method = 'GET', body) {
    const response = await fetch('/_sandstorm/network', {
      method,
      headers: {
        'Content-Type': 'application/json',
        'X-Sandstorm-App-Network': '1',
      },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    if (!response.ok) throw new Error(await response.text());
    if (method === 'GET') return response.json();
  }

  function chooseNetwork(descriptor, label) {
    return new Promise((resolve, reject) => {
      const rpcId = 'powerbox-network-' + Array.from(
        crypto.getRandomValues(new Uint32Array(4)), n => n.toString(16),
      ).join('-');
      const receive = event => {
        if (event.source !== window.parent || event.data?.rpcId !== rpcId) return;
        window.removeEventListener('message', receive);
        if (event.data.token) resolve(event.data.token);
        else reject(new Error(event.data.error || 'Network selection canceled'));
      };
      window.addEventListener('message', receive);
      try {
        window.parent.postMessage({powerboxRequest: {
          rpcId,
          query: [descriptor],
          saveLabel: {defaultText: label},
        }}, '*');
      } catch (error) {
        window.removeEventListener('message', receive);
        reject(error);
      }
    });
  }

  window.powerboxNetwork = {
    status: () => request(),
    async connect(label = 'Network access') {
      if (connecting) throw new Error('Network selection already in progress');
      connecting = true;
      try {
        const state = await request();
        if (state.configured) throw new Error('Disconnect the existing network first');
        const token = await chooseNetwork(state.descriptor, label);
        await request('POST', {token});
      } finally {
        connecting = false;
      }
    },
    disconnect: () => request('DELETE'),
  };
})();

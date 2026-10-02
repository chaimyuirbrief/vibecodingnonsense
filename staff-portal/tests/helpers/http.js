// Drive the real worker `fetch` end to end (SPEC §13.2): build a Request, set
// the client-IP header the platform uses, attach `request.cf`, call
// worker.fetch, and keep cookies in a jar between calls.
//
//   const c = new Client(worker, env, { ip: '198.51.100.7' });
//   const r = await c.post('/api/auth/login', { identifier, password });
//   r.status, r.body (parsed JSON or null), r.text, r.res, r.headers
//
// Every Client is one "browser": its own cookie jar, IP, UA and cf object.

export const CHROME_UA =
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36';
export const FIREFOX_UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:131.0) Gecko/20100101 Firefox/131.0';
export const SAFARI_IOS_UA =
  'Mozilla/5.0 (iPhone; CPU iPhone OS 17_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Mobile/15E148 Safari/604.1';

export class Client {
  constructor(worker, env, { ip = '203.0.113.10', ua = CHROME_UA, cf = {}, headers = {} } = {}) {
    this.worker = worker;
    this.env = env;
    this.ip = ip;
    this.ua = ua;
    this.cf = { country: 'US', asn: 7922, asOrganization: 'Comcast Cable', colo: 'EWR', tlsVersion: 'TLSv1.3', tlsCipher: 'AEAD-AES128-GCM-SHA256', httpProtocol: 'HTTP/2', timezone: 'America/New_York', city: 'Newark', ...cf };
    this.extraHeaders = headers;
    this.jar = new Map();
    this.waitUntil = [];
  }

  cookieHeader() {
    return [...this.jar.entries()].map(([k, v]) => `${k}=${v}`).join('; ');
  }

  absorb(res) {
    const list = typeof res.headers.getSetCookie === 'function' ? res.headers.getSetCookie() : [];
    for (const sc of list) {
      const [pair, ...attrs] = sc.split(';');
      const i = pair.indexOf('=');
      const name = pair.slice(0, i).trim();
      const value = pair.slice(i + 1).trim();
      const maxAge = attrs.map((a) => a.trim()).find((a) => /^max-age=/i.test(a));
      if (value === '' || (maxAge && Number(maxAge.split('=')[1]) <= 0)) this.jar.delete(name);
      else this.jar.set(name, value);
    }
  }

  async request(method, path, body, headers = {}) {
    const url = new URL(path, this.env.ORIGIN);
    const h = new Headers({
      'cf-connecting-ip': this.ip,
      'user-agent': this.ua,
      'accept-language': 'en-US,en;q=0.9',
      accept: body === undefined && method === 'GET' ? 'text/html,application/json;q=0.9,*/*;q=0.8' : 'application/json',
      ...this.extraHeaders,
      ...headers,
    });
    if (method !== 'GET' && method !== 'HEAD' && !h.has('origin')) h.set('origin', this.env.ORIGIN);
    if (body !== undefined && !h.has('content-type')) h.set('content-type', 'application/json');
    const cookies = this.cookieHeader();
    if (cookies && !h.has('cookie')) h.set('cookie', cookies);
    const req = new Request(url, { method, headers: h, body: body === undefined ? undefined : typeof body === 'string' ? body : JSON.stringify(body) });
    Object.defineProperty(req, 'cf', { value: { ...this.cf }, enumerable: true });
    const pending = [];
    const ctx = { waitUntil: (p) => pending.push(Promise.resolve(p)), passThroughOnException() {} };
    const res = await this.worker.fetch(req, this.env, ctx);
    await Promise.allSettled(pending);
    this.absorb(res);
    const text = await res.text();
    let parsed = null;
    try {
      parsed = text ? JSON.parse(text) : null;
    } catch {
      parsed = null;
    }
    return { status: res.status, body: parsed, text, res, headers: res.headers };
  }

  get(path, headers) {
    return this.request('GET', path, undefined, headers);
  }
  post(path, body = {}, headers) {
    return this.request('POST', path, body, headers);
  }
  put(path, body = {}, headers) {
    return this.request('PUT', path, body, headers);
  }
  patch(path, body = {}, headers) {
    return this.request('PATCH', path, body, headers);
  }
  del(path, body, headers) {
    return this.request('DELETE', path, body, headers);
  }
}

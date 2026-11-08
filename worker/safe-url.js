// ScamSense AI: SSRF-safe URL handling for the Website Investigator.
//
// Everything that touches a user-supplied URL goes through this file.
//   parsePublicUrl()   validates a URL and rejects anything that is not a public http(s) address.
//   resolvePublicHost() resolves a hostname over DNS-over-HTTPS and rejects private/reserved answers.
//   safeFetch()        fetches with MANUAL redirects, re-validating every hop, with time and size caps.
//
// Honest limits (also shown to the person in the report):
//   * A Cloudflare Worker cannot pin the IP address it connects to, so the DNS check is defence in depth,
//     not a guarantee against DNS rebinding. Cloudflare's network also refuses to connect Workers to private
//     address space, which is the primary protection.
//   * Only GET requests are made. No cookies or credentials are ever sent. Only ports 80 and 443 are used.

const MAX_URL_CHARS = 2048;
const FETCH_UA = "Mozilla/5.0 (compatible; ScamSenseInvestigator/1.0; +https://kingalikid00-sketch.github.io/scamsense-ai/)";
const DOH_URL = "https://cloudflare-dns.com/dns-query";

const BLOCKED_SUFFIXES = [".localhost", ".local", ".internal", ".lan", ".home", ".home.arpa", ".corp", ".intranet", ".private", ".test", ".invalid", ".example"];

// ---------------------------------------------------------------- IP classification

export function parseIPv4(s) {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(s);
  if (!m) return null;
  const p = [m[1], m[2], m[3], m[4]].map(Number);
  return p.some((n) => n > 255) ? null : p;
}

export function isPrivateIPv4(p) {
  const [a, b, c] = p;
  if (a === 0 || a === 10 || a === 127) return true;
  if (a === 100 && b >= 64 && b <= 127) return true;        // carrier-grade NAT
  if (a === 169 && b === 254) return true;                  // link-local, cloud metadata
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 192 && b === 0 && c === 0) return true;
  if (a === 192 && b === 0 && c === 2) return true;         // TEST-NET-1
  if (a === 192 && b === 88 && c === 99) return true;
  if (a === 192 && b === 168) return true;
  if (a === 198 && (b === 18 || b === 19)) return true;     // benchmarking
  if (a === 198 && b === 51 && c === 100) return true;      // TEST-NET-2
  if (a === 203 && b === 0 && c === 113) return true;      // TEST-NET-3
  if (a >= 224) return true;                                // multicast, reserved, broadcast
  return false;
}

// Expands an IPv6 literal (no brackets) into 8 16-bit groups, or null if it is not valid.
export function parseIPv6(input) {
  let s = String(input).toLowerCase();
  if (s.includes("%")) s = s.split("%")[0];
  if (!/^[0-9a-f:.]+$/.test(s) || !s.includes(":")) return null;
  let tail = [];
  const lastColon = s.lastIndexOf(":");
  const maybeV4 = s.slice(lastColon + 1);
  if (maybeV4.includes(".")) {
    const v4 = parseIPv4(maybeV4);
    if (!v4) return null;
    tail = [(v4[0] << 8) | v4[1], (v4[2] << 8) | v4[3]];
    s = s.slice(0, lastColon + 1) + "0:0";
  }
  const halves = s.split("::");
  if (halves.length > 2) return null;
  const parse = (str) => (str === "" ? [] : str.split(":"));
  const head = parse(halves[0]);
  const rest = halves.length === 2 ? parse(halves[1]) : [];
  const all = halves.length === 2 ? null : head;
  let groups;
  if (all) {
    if (all.length !== 8) return null;
    groups = all;
  } else {
    const missing = 8 - head.length - rest.length;
    if (missing < 1) return null;
    groups = head.concat(new Array(missing).fill("0"), rest);
  }
  const out = [];
  for (const g of groups) {
    if (!/^[0-9a-f]{1,4}$/.test(g)) return null;
    out.push(parseInt(g, 16));
  }
  if (tail.length) { out[6] = tail[0]; out[7] = tail[1]; }
  return out.length === 8 ? out : null;
}

export function isPrivateIPv6(g) {
  const allZeroUpTo = (n) => g.slice(0, n).every((x) => x === 0);
  if (allZeroUpTo(7) && (g[7] === 0 || g[7] === 1)) return true;   // :: and ::1
  const embedded = [g[6] >> 8, g[6] & 255, g[7] >> 8, g[7] & 255];
  if (allZeroUpTo(5) && g[5] === 0xffff) return isPrivateIPv4(embedded);   // ::ffff:a.b.c.d (IPv4-mapped)
  if (allZeroUpTo(6)) return true;                                          // ::a.b.c.d (deprecated IPv4-compatible)
  if (g[0] === 0x64 && g[1] === 0xff9b && g.slice(2, 6).every((x) => x === 0)) return isPrivateIPv4(embedded); // NAT64
  if ((g[0] & 0xfe00) === 0xfc00) return true;                              // unique local fc00::/7
  if ((g[0] & 0xffc0) === 0xfe80) return true;                              // link-local fe80::/10
  if ((g[0] & 0xffc0) === 0xfec0) return true;                              // site-local (deprecated)
  if ((g[0] & 0xff00) === 0xff00) return true;                              // multicast
  if (g[0] === 0x2001 && g[1] === 0x0db8) return true;                      // documentation
  if (g[0] === 0x2001 && g[1] === 0) return true;                           // Teredo
  if (g[0] === 0x2002) return isPrivateIPv4([g[1] >> 8, g[1] & 255, g[2] >> 8, g[2] & 255]); // 6to4
  if (g[0] === 0x0100 && g[1] === 0 && g[2] === 0 && g[3] === 0) return true; // discard-only
  return false;
}

// true = the address is private, reserved or unparseable (treat as unsafe).
export function isUnsafeIp(ip) {
  const v4 = parseIPv4(ip);
  if (v4) return isPrivateIPv4(v4);
  const v6 = parseIPv6(ip);
  if (v6) return isPrivateIPv6(v6);
  return true;
}

// ---------------------------------------------------------------- URL validation

// Returns { ok:true, url:URL, host, hadScheme, credentials, port } or { ok:false, reason, code }.
export function parsePublicUrl(raw) {
  let s = typeof raw === "string" ? raw.trim() : "";
  if (!s) return { ok: false, code: "empty", reason: "Please enter a web address." };
  if (s.length > MAX_URL_CHARS) return { ok: false, code: "too-long", reason: "That web address is too long." };
  if (/[\u0000-\u001f\u007f\s]/.test(s)) return { ok: false, code: "bad-chars", reason: "That web address contains spaces or hidden characters." };
  const schemeMatch = /^([a-z][a-z0-9+.-]*):/i.exec(s);
  const hadScheme = !!(schemeMatch && /^[a-z][a-z0-9+.-]*:\/\//i.test(s));
  if (hadScheme && !/^https?:\/\//i.test(s)) return { ok: false, code: "scheme", reason: "Only http and https web addresses can be investigated." };
  if (!hadScheme && /^(javascript|data|file|ftp|mailto|tel|sms|blob|about|gopher|ws|wss):/i.test(s)) return { ok: false, code: "scheme", reason: "Only http and https web addresses can be investigated." };
  if (!hadScheme) s = "https://" + s.replace(/^\/+/, "");
  let url;
  try { url = new URL(s); } catch (e) { return { ok: false, code: "invalid", reason: "That doesn't look like a valid web address." }; }
  if (url.protocol !== "http:" && url.protocol !== "https:") return { ok: false, code: "scheme", reason: "Only http and https web addresses can be investigated." };

  const credentials = !!(url.username || url.password);
  let host = url.hostname.toLowerCase();
  if (host.endsWith(".")) host = host.slice(0, -1);
  if (!host) return { ok: false, code: "invalid", reason: "That doesn't look like a valid web address." };

  const port = url.port ? Number(url.port) : (url.protocol === "https:" ? 443 : 80);
  const isIpLiteral = host.startsWith("[") || !!parseIPv4(host);
  if (isIpLiteral) {
    const bare = host.startsWith("[") ? host.slice(1, -1) : host;
    if (isUnsafeIp(bare)) return { ok: false, code: "private", reason: "That address points to a private or reserved network, so it can't be investigated." };
  } else {
    if (host === "localhost" || BLOCKED_SUFFIXES.some((x) => host.endsWith(x))) return { ok: false, code: "private", reason: "That address points to a private or internal network, so it can't be investigated." };
    if (!host.includes(".")) return { ok: false, code: "private", reason: "That address has no public domain name, so it can't be investigated." };
    if (/^[0-9.]+$/.test(host) || /^0x[0-9a-f]+$/i.test(host)) return { ok: false, code: "private", reason: "That address is written in an unusual numeric form and can't be investigated." };
    if (host.length > 253 || host.split(".").some((l) => l.length === 0 || l.length > 63)) return { ok: false, code: "invalid", reason: "That doesn't look like a valid web address." };
  }
  return { ok: true, url, host, hadScheme, credentials, port, isIpLiteral };
}

// Only the standard web ports are ever contacted.
export function portAllowed(port) { return port === 80 || port === 443; }

// ---------------------------------------------------------------- DNS (DNS-over-HTTPS)

async function dohQuery(name, type, signal) {
  const res = await fetch(DOH_URL + "?name=" + encodeURIComponent(name) + "&type=" + type, { headers: { Accept: "application/dns-json" }, signal });
  if (!res.ok) throw new Error("doh-http");
  return res.json();
}

// Resolves A and AAAA records and refuses to continue if ANY answer is private or reserved.
// Returns { ok, addresses[], reason, code }.
export async function resolvePublicHost(host, timeoutMs) {
  const bare = host.startsWith("[") ? host.slice(1, -1) : host;
  if (parseIPv4(bare) || parseIPv6(bare)) {
    return isUnsafeIp(bare) ? { ok: false, code: "private", reason: "private address", addresses: [] } : { ok: true, addresses: [bare] };
  }
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs || 4000);
  try {
    const [a, aaaa] = await Promise.all([dohQuery(bare, "A", controller.signal), dohQuery(bare, "AAAA", controller.signal)]);
    const addresses = [];
    for (const r of [a, aaaa]) for (const ans of (r && r.Answer) || []) if ((ans.type === 1 || ans.type === 28) && typeof ans.data === "string") addresses.push(ans.data);
    if (!addresses.length) {
      const nx = a && a.Status === 3;
      return { ok: false, code: nx ? "nxdomain" : "no-records", reason: nx ? "This domain name does not exist." : "This domain name has no web address records.", addresses: [] };
    }
    if (addresses.some(isUnsafeIp)) return { ok: false, code: "private", reason: "This domain points to a private or reserved network.", addresses };
    return { ok: true, addresses };
  } catch (e) {
    return { ok: false, code: "dns-error", reason: "The domain name lookup did not complete.", addresses: [] };
  } finally {
    clearTimeout(timer);
  }
}

// ---------------------------------------------------------------- guarded fetch

async function readCapped(res, maxBytes) {
  if (!res.body) return "";
  const reader = res.body.getReader();
  const chunks = [];
  let total = 0;
  while (total < maxBytes) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    chunks.push(value);
  }
  try { await reader.cancel(); } catch (e) { /* ignore */ }
  const buf = new Uint8Array(Math.min(total, maxBytes));
  let off = 0;
  for (const c of chunks) {
    const take = Math.min(c.byteLength, buf.length - off);
    if (take <= 0) break;
    buf.set(c.subarray(0, take), off);
    off += take;
  }
  return new TextDecoder("utf-8", { fatal: false }).decode(buf);
}

// Follows redirects by hand so every hop is validated. Never throws; returns a structured outcome.
// { hops:[{url,status,location}], final:{url,status,headers,body,contentType}|null, error:{code,reason}|null }
export async function safeFetch(startUrl, opts) {
  const o = Object.assign({ maxRedirects: 5, timeoutMs: 9000, maxBytes: 524288 }, opts || {});
  const hops = [];
  let current = startUrl;
  const deadline = Date.now() + o.timeoutMs;

  for (let i = 0; i <= o.maxRedirects; i++) {
    const p = parsePublicUrl(current);
    if (!p.ok) return { hops, final: null, error: { code: p.code === "private" ? "blocked" : p.code, reason: i === 0 ? p.reason : "A redirect led to an address that can't be followed safely (" + p.reason + ")" } };
    if (!portAllowed(p.port)) return { hops, final: null, error: { code: "port", reason: "The address uses a non-standard port, which ScamSense does not contact. That is itself worth noting." } };
    const dns = await resolvePublicHost(p.host, 4000);
    if (!dns.ok) return { hops, final: null, error: { code: dns.code === "private" ? "blocked" : dns.code, reason: dns.reason } };

    const left = deadline - Date.now();
    if (left < 500) return { hops, final: null, error: { code: "timeout", reason: "The site took too long to respond." } };
    const clean = new URL(p.url.href);
    clean.username = ""; clean.password = ""; clean.hash = "";
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), left);
    let res;
    try {
      res = await fetch(clean.href, {
        method: "GET",
        redirect: "manual",
        signal: controller.signal,
        headers: { "User-Agent": FETCH_UA, Accept: "text/html,application/xhtml+xml;q=0.9,*/*;q=0.5", "Accept-Language": "en", DNT: "1" },
      });
    } catch (e) {
      clearTimeout(timer);
      const aborted = e && e.name === "AbortError";
      return { hops, final: null, error: { code: aborted ? "timeout" : "connect", reason: aborted ? "The site took too long to respond." : "The site could not be reached (it may be offline, blocking automated visits, or have a certificate problem)." } };
    }

    if (res.status >= 300 && res.status < 400 && res.headers.get("location")) {
      clearTimeout(timer);
      let next;
      try { next = new URL(res.headers.get("location"), clean.href).href; } catch (e) { return { hops, final: null, error: { code: "bad-redirect", reason: "The site sent an invalid redirect." } }; }
      hops.push({ url: clean.href, status: res.status, location: next });
      try { await res.body && res.body.cancel(); } catch (e) { /* ignore */ }
      current = next;
      continue;
    }

    const contentType = (res.headers.get("content-type") || "").toLowerCase();
    let body = "";
    if (/text\/html|application\/xhtml|text\/plain/.test(contentType) || !contentType) {
      try { body = await readCapped(res, o.maxBytes); } catch (e) { body = ""; }
    } else {
      try { await res.body && res.body.cancel(); } catch (e) { /* ignore */ }
    }
    clearTimeout(timer);
    const keep = {};
    for (const k of ["strict-transport-security", "content-type", "server", "x-frame-options", "content-security-policy", "x-content-type-options", "referrer-policy"]) {
      const v = res.headers.get(k);
      if (v) keep[k] = v.slice(0, 300);
    }
    return { hops, final: { url: clean.href, status: res.status, headers: keep, body, contentType }, error: null };
  }
  return { hops, final: null, error: { code: "too-many-redirects", reason: "The address redirected more than " + o.maxRedirects + " times." } };
}

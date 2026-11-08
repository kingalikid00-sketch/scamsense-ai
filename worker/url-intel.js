// ScamSense AI: Website and Phishing Investigator engine.
//
// Produces a structured, evidence-based report for one URL. Rules this file follows:
//   * Every statement in the report comes from a check that actually ran. A check that could not run is
//     reported as "unavailable" or "not_configured", never guessed.
//   * HTTPS never lowers risk. The verdict can never be "safe": the best outcome is "no_issues_found",
//     and it is only given when the page was loaded AND at least one reputation database answered.
//   * A threat-intelligence listing is reported as the provider's finding, not as ScamSense's proof.
//
// Optional secrets (Cloudflare Worker secrets; each one switches on one provider):
//   GOOGLE_SAFE_BROWSING_KEY   Google Safe Browsing v4 Lookup API
//   VIRUSTOTAL_API_KEY         VirusTotal v3 (lookup only: ScamSense never submits a URL for public scanning)
//   URLHAUS_AUTH_KEY           abuse.ch URLhaus (malware distribution URLs)

import { parsePublicUrl, safeFetch, parseIPv4, portAllowed } from "./safe-url.js";

// ---------------------------------------------------------------- reference data

const MULTI_SUFFIXES = new Set([
  "co.uk", "org.uk", "gov.uk", "ac.uk", "me.uk", "ltd.uk", "plc.uk", "net.uk", "sch.uk",
  "com.ng", "org.ng", "gov.ng", "edu.ng", "net.ng", "com.gh", "org.gh", "gov.gh", "edu.gh",
  "co.za", "org.za", "gov.za", "ac.za", "co.ke", "or.ke", "go.ke", "com.eg", "co.tz", "co.ug", "co.zw",
  "com.au", "net.au", "org.au", "gov.au", "edu.au", "co.nz", "co.in", "net.in", "org.in", "gov.in",
  "com.br", "com.mx", "com.ar", "com.co", "com.pe", "co.jp", "or.jp", "com.cn", "com.hk", "com.sg", "com.my",
  "com.tr", "com.ph", "com.pk", "com.bd", "co.id", "com.vn", "com.sa", "co.il", "com.ua", "com.pl",
]);

// Free site-building / hosting platforms: the registrable "site" is one label to the left of these.
const FREE_HOSTS = new Set([
  "blogspot.com", "github.io", "pages.dev", "workers.dev", "vercel.app", "netlify.app", "web.app", "firebaseapp.com",
  "weebly.com", "wixsite.com", "webflow.io", "herokuapp.com", "glitch.me", "repl.co", "replit.app", "carrd.co",
  "godaddysites.com", "000webhostapp.com", "wordpress.com", "sites.google.com", "onrender.com", "fly.dev", "netlify.com",
  "framer.website", "framer.app", "my.canva.site", "typedream.app", "webcindario.com", "ukit.me", "square.site",
]);

const SHORTENERS = new Set([
  "bit.ly", "tinyurl.com", "t.co", "cutt.ly", "is.gd", "rb.gy", "shorturl.at", "ow.ly", "buff.ly", "tiny.cc",
  "goo.gl", "lnkd.in", "s.id", "t.ly", "v.gd", "rebrand.ly", "bl.ink", "short.io", "soo.gd", "clck.ru", "qr.ae", "l.wl.co",
]);

const RISKY_TLDS = new Set(["zip", "mov", "top", "xyz", "click", "icu", "buzz", "work", "support", "rest", "gq", "tk", "ml", "cf", "ga", "cfd", "sbs", "monster", "quest", "cyou", "bond", "lol", "fit", "country", "stream"]);

const HOST_KEYWORDS = /(login|log-in|signin|sign-in|verify|verification|secure|security|account|update|wallet|billing|confirm|recover|unlock|support|helpdesk|claim|reward|bonus|giveaway|airdrop|refund|invoice|payment)/i;

// Brands are matched as whole label tokens (never as raw substrings) to avoid false accusations.
// Official domains are the ones ScamSense can state with confidence; anything else is reported as
// "does not match the domains we have on file", never as proof of fraud.
const BRANDS = [
  { name: "PayPal", tokens: ["paypal"], domains: ["paypal.com", "paypal.me"] },
  { name: "Amazon", tokens: ["amazon"], domains: ["amazon.com", "amazon.co.uk", "amazon.de", "amazon.fr", "amazon.it", "amazon.es", "amazon.ca", "amazon.com.au", "amazon.co.jp", "amazon.in", "amazon.com.br", "amazon.com.mx", "amazon.ae", "amazon.sa", "amazon.eg", "amazon.se", "amazon.nl", "amazon.pl", "amazon.sg", "amazon.com.tr"] },
  { name: "Apple", tokens: ["apple", "icloud", "appleid"], domains: ["apple.com", "icloud.com"] },
  { name: "Google", tokens: ["google", "gmail"], domains: ["google.com", "google.co.uk", "google.com.ng", "google.com.gh", "google.ca", "google.com.au", "google.de", "google.fr", "google.co.in", "google.co.za", "gmail.com"] },
  { name: "Microsoft", tokens: ["microsoft", "office365", "outlook"], domains: ["microsoft.com", "live.com", "office.com", "microsoftonline.com", "outlook.com", "windows.com", "office365.com"] },
  { name: "Netflix", tokens: ["netflix"], domains: ["netflix.com"] },
  { name: "Facebook / Meta", tokens: ["facebook", "meta", "messenger"], domains: ["facebook.com", "fb.com", "fb.me", "meta.com", "messenger.com"] },
  { name: "Instagram", tokens: ["instagram"], domains: ["instagram.com"] },
  { name: "WhatsApp", tokens: ["whatsapp"], domains: ["whatsapp.com", "wa.me", "whatsapp.net"] },
  { name: "DHL", tokens: ["dhl"], domains: ["dhl.com", "dhl.de", "dhl.co.uk"] },
  { name: "FedEx", tokens: ["fedex"], domains: ["fedex.com"] },
  { name: "UPS", tokens: ["ups"], domains: ["ups.com"] },
  { name: "USPS", tokens: ["usps"], domains: ["usps.com"] },
  { name: "Binance", tokens: ["binance"], domains: ["binance.com", "binance.us"] },
  { name: "Coinbase", tokens: ["coinbase"], domains: ["coinbase.com"] },
  { name: "Chase", tokens: ["chase"], domains: ["chase.com", "jpmorganchase.com"] },
  { name: "Wells Fargo", tokens: ["wellsfargo"], domains: ["wellsfargo.com"] },
  { name: "Bank of America", tokens: ["bankofamerica"], domains: ["bankofamerica.com"] },
  { name: "Paystack", tokens: ["paystack"], domains: ["paystack.com", "paystack.co"] },
  { name: "Flutterwave", tokens: ["flutterwave"], domains: ["flutterwave.com"] },
  { name: "GTBank", tokens: ["gtbank"], domains: ["gtbank.com"] },
  { name: "Zenith Bank", tokens: ["zenithbank"], domains: ["zenithbank.com"] },
  { name: "Access Bank", tokens: ["accessbankplc", "accessbank"], domains: ["accessbankplc.com"] },
  { name: "First Bank of Nigeria", tokens: ["firstbanknigeria"], domains: ["firstbanknigeria.com"] },
  { name: "Kuda", tokens: ["kuda"], domains: ["kuda.com"] },
  { name: "Moniepoint", tokens: ["moniepoint"], domains: ["moniepoint.com"] },
  { name: "PalmPay", tokens: ["palmpay"], domains: ["palmpay.com"] },
];

const BRAND_SUFFIX_WORDS = new Set(["secure", "login", "signin", "verify", "verification", "support", "help", "helpdesk", "account", "accounts", "wallet", "pay", "payment", "payments", "online", "service", "services", "update", "app", "official", "ng", "gh", "uk", "us", "customer", "care", "team", "id", "web", "portal", "claim", "reward", "bonus", "billing", "security"]);

// ---------------------------------------------------------------- domain helpers

export function registrableInfo(host) {
  const h = host.toLowerCase();
  if (parseIPv4(h) || h.includes(":")) return { registrable: h, labels: [h], subdomains: [], suffix: "", freeHost: false, ip: true };
  const parts = h.split(".");
  let suffixLen = 1;
  const last2 = parts.slice(-2).join(".");
  if (parts.length >= 3 && MULTI_SUFFIXES.has(last2)) suffixLen = 2;
  let freeHost = false;
  for (let n = Math.min(3, parts.length - 1); n >= 2; n--) {
    if (FREE_HOSTS.has(parts.slice(-n).join("."))) { suffixLen = n; freeHost = true; break; }
  }
  if (!freeHost && FREE_HOSTS.has(last2)) { suffixLen = 2; freeHost = true; }
  const regParts = parts.slice(-(suffixLen + 1));
  return {
    registrable: regParts.join("."),
    label: regParts[0],
    suffix: parts.slice(-suffixLen).join("."),
    tld: parts[parts.length - 1],
    subdomains: parts.slice(0, Math.max(0, parts.length - suffixLen - 1)),
    freeHost,
    ip: false,
  };
}

function isOfficial(brand, registrable) { return brand.domains.includes(registrable); }

function levenshtein(a, b) {
  if (a === b) return 0;
  if (!a.length) return b.length;
  if (!b.length) return a.length;
  let prev = Array.from({ length: b.length + 1 }, (_, i) => i);
  for (let i = 1; i <= a.length; i++) {
    const cur = [i];
    for (let j = 1; j <= b.length; j++) {
      cur[j] = Math.min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1));
    }
    prev = cur;
  }
  return prev[b.length];
}

function homoglyphVariants(s) {
  const base = s.replace(/rn/g, "m").replace(/vv/g, "w").replace(/0/g, "o").replace(/5/g, "s").replace(/3/g, "e").replace(/4/g, "a");
  return [base.replace(/1/g, "l"), base.replace(/1/g, "i")];
}

function labelTokens(s) { return s.split(/[^a-z0-9]+/).filter(Boolean); }

function tokenMatchesBrand(tok, brandTok) {
  if (tok === brandTok) return true;
  if (tok.startsWith(brandTok) && BRAND_SUFFIX_WORDS.has(tok.slice(brandTok.length))) return true;
  if (tok.endsWith(brandTok) && BRAND_SUFFIX_WORDS.has(tok.slice(0, tok.length - brandTok.length))) return true;
  return false;
}

// Brand impersonation signals for a hostname. Pure function.
export function brandSignals(host) {
  const info = registrableInfo(host);
  const out = [];
  if (info.ip) return out;
  const seen = new Set();
  for (const brand of BRANDS) {
    if (isOfficial(brand, info.registrable)) continue;
    const subTokens = info.subdomains.flatMap(labelTokens);
    const domTokens = labelTokens(info.label || "");
    for (const bt of brand.tokens) {
      let kind = "";
      if (subTokens.some((t) => tokenMatchesBrand(t, bt))) kind = "subdomain";
      else if (domTokens.some((t) => tokenMatchesBrand(t, bt))) kind = "domain";
      else if (bt.length >= 5) {
        for (const t of domTokens) {
          if (t.length < 5) continue;
          const variants = [t].concat(homoglyphVariants(t));
          // An exact match after swapping look-alike characters (paypa1 -> paypal, arnazon -> amazon) counts too.
          if (t !== bt && variants.some((v) => v === bt || levenshtein(v, bt) <= (bt.length >= 8 ? 2 : 1))) { kind = "lookalike"; break; }
        }
      }
      if (kind && !seen.has(brand.name)) {
        seen.add(brand.name);
        out.push({ brand: brand.name, kind, official: brand.domains.slice(0, 3) });
      }
    }
  }
  return out;
}

// ---------------------------------------------------------------- static signals (no network)

function ind(id, severity, title, detail, evidence) {
  return { id, severity, title, detail, evidence: evidence || "" };
}

// Signals visible in the address itself. Pure function: safe to run on every link in a message.
export function staticUrlSignals(parsed) {
  const out = [];
  const { url, host, hadScheme, credentials, port, isIpLiteral } = parsed;
  const info = registrableInfo(host);

  if (credentials) out.push(ind("userinfo", "high", "The address contains a hidden “user@” part", "Text before an @ sign in a web address is not the website. It is often used to make a link look like it goes somewhere familiar. The real destination of this link is " + host + ".", url.href.slice(0, 120)));
  if (isIpLiteral) out.push(ind("ip-host", "medium", "The address is a number, not a name", "Legitimate services almost always use a domain name. Scam pages sometimes use a raw IP address to avoid domain checks.", host));
  if (host.split(".").some((l) => l.startsWith("xn--"))) out.push(ind("punycode", "medium", "The domain uses look-alike characters", "The name is encoded with international characters (xn--). Attackers use letters from other alphabets that look identical to Latin letters.", host));
  if (url.protocol === "http:" && hadScheme) out.push(ind("http", "low", "The address does not use encryption (http)", "Information typed on an http page can be read by others on the network. Many real sites are https only.", url.protocol + "//" + host));
  if (!isIpLiteral && info.subdomains.length >= 3) out.push(ind("deep-subdomain", "medium", "Unusually many sub-domains", "Long chains of sub-domains can push the real domain out of sight on a small screen. The real domain here is " + info.registrable + ".", host));
  if (!isIpLiteral && info.label && (info.label.match(/-/g) || []).length >= 3) out.push(ind("many-dashes", "low", "Many dashes in the domain name", "Scam domains often chain words with dashes (for example bank-secure-login-help).", info.registrable));
  if (!isIpLiteral && !info.freeHost && RISKY_TLDS.has(info.tld)) out.push(ind("risky-tld", "low", "Domain ending often seen in abuse (." + info.tld + ")", "Some endings are cheap or free, so they are over-represented in scams. Many legitimate sites also use them, so this alone means little.", "." + info.tld));
  if (!isIpLiteral && info.freeHost) out.push(ind("free-host", "low", "Hosted on a free site-building platform (" + info.registrable + ")", "Anyone can create a page here in minutes, so the platform name says nothing about who runs this page.", host));
  if (!isIpLiteral && SHORTENERS.has(info.registrable)) out.push(ind("shortener", "medium", "Shortened link", "A short link hides its real destination. ScamSense followed it to see where it leads.", host));
  const kw = !isIpLiteral && HOST_KEYWORDS.exec(host.replace(info.registrable, "") + " " + (info.label || ""));
  if (kw) out.push(ind("host-keyword", "low", "Pressure or account words in the domain (“" + kw[0].toLowerCase() + "”)", "Real companies rarely put words like login, verify or secure in a domain that is not their main domain.", host));
  if (!portAllowed(port)) out.push(ind("port", "medium", "Non-standard port (" + port + ")", "Normal websites use the standard web ports. ScamSense does not contact other ports.", host + ":" + port));
  if (url.href.length > 200) out.push(ind("long-url", "low", "Very long address", "Very long addresses can hide the important part.", url.href.slice(0, 80) + "…"));
  for (const b of brandSignals(host)) {
    const off = b.official.join(", ");
    if (b.kind === "subdomain") out.push(ind("brand-subdomain", "high", "Uses the name “" + b.brand + "” in front of a different domain", "The real domain of this address is " + info.registrable + ", which is not a " + b.brand + " domain we have on file (" + off + "). Putting a brand name on the left is a classic disguise.", host));
    else if (b.kind === "lookalike") out.push(ind("brand-lookalike", "high", "Domain closely imitates “" + b.brand + "”", "The name is one or two characters away from a known brand, or swaps letters for look-alike digits. It is not one of the " + b.brand + " domains we have on file (" + off + ").", info.registrable));
    else out.push(ind("brand-name", "medium", "Uses the name “" + b.brand + "” but is not a " + b.brand + " domain we have on file", "Domains we have on file for " + b.brand + ": " + off + ". If you expected the real " + b.brand + ", open its official app or type its address yourself.", info.registrable));
  }
  return out;
}

// Quick check for links found inside a pasted message. No network. Returns null for unparseable input.
export function quickLinkCheck(raw) {
  const p = parsePublicUrl(raw);
  if (!p.ok) return null;
  const signals = staticUrlSignals(p);
  return { url: p.url.href.slice(0, 300), host: p.host, indicators: signals };
}

// ---------------------------------------------------------------- HTML analysis

const SENSITIVE_FIELD_PATTERNS = [
  { re: /(cc[-_ ]?number|card[-_ ]?number|cardnum|credit[-_ ]?card|debit[-_ ]?card)/i, label: "a card number" },
  { re: /\b(cvv|cvc|cvv2|security[-_ ]?code)\b/i, label: "a card security code (CVV)" },
  { re: /(one[-_ ]?time|otp|verification[-_ ]?code|sms[-_ ]?code|2fa|auth[-_ ]?code)/i, label: "a one-time or verification code" },
  { re: /\b(pin|atm[-_ ]?pin)\b/i, label: "a PIN" },
  { re: /\b(bvn|nin)\b/i, label: "a national or bank identity number (BVN/NIN)" },
  { re: /(ssn|social[-_ ]?security)/i, label: "a social security number" },
  { re: /(seed[-_ ]?phrase|recovery[-_ ]?phrase|secret[-_ ]?phrase|mnemonic|private[-_ ]?key|12[-_ ]?words)/i, label: "a crypto wallet recovery phrase or private key" },
];

function attr(tag, name) {
  const m = new RegExp("\\b" + name + "\\s*=\\s*(\"([^\"]*)\"|'([^']*)'|([^\\s>]+))", "i").exec(tag);
  return m ? (m[2] !== undefined ? m[2] : (m[3] !== undefined ? m[3] : m[4])) : "";
}

export function analyzeHtml(html, pageUrl) {
  const body = String(html || "");
  const page = new URL(pageUrl);
  const pageReg = registrableInfo(page.hostname).registrable;
  const r = {
    loaded: body.length > 0, textLength: 0, title: "", forms: 0, passwordFields: 0, sensitiveFields: [],
    crossDomainForms: [], insecureFormActions: [], hiddenIframes: 0, metaRefresh: "", jsRedirect: false, obfuscatedScript: false, brandInTitle: [],
  };
  if (!body) return r;
  const t = /<title[^>]*>([\s\S]*?)<\/title>/i.exec(body);
  if (t) r.title = t[1].replace(/<[^>]+>/g, "").replace(/\s+/g, " ").trim().slice(0, 160);
  r.textLength = body.replace(/<script[\s\S]*?<\/script>/gi, "").replace(/<style[\s\S]*?<\/style>/gi, "").replace(/<[^>]+>/g, " ").replace(/\s+/g, " ").trim().length;

  const mr = /<meta[^>]+http-equiv\s*=\s*["']?refresh["']?[^>]*content\s*=\s*["']?\s*\d+\s*;\s*url=([^"'>\s]+)/i.exec(body);
  if (mr) r.metaRefresh = mr[1].slice(0, 200);

  const forms = body.match(/<form\b[^>]*>/gi) || [];
  r.forms = forms.length;
  for (const f of forms) {
    const action = attr(f, "action").trim();
    if (!action || action.startsWith("#") || /^javascript:/i.test(action)) continue;
    try {
      const u = new URL(action, page.href);
      if (u.protocol === "http:" && page.protocol === "https:") r.insecureFormActions.push(u.hostname);
      const reg = registrableInfo(u.hostname).registrable;
      if (reg !== pageReg && /^https?:$/.test(u.protocol)) r.crossDomainForms.push(u.hostname);
    } catch (e) { /* ignore unparseable action */ }
  }

  const inputs = body.match(/<input\b[^>]*>/gi) || [];
  const found = new Set();
  for (const i of inputs) {
    const type = attr(i, "type").toLowerCase();
    if (type === "password") r.passwordFields++;
    if (type === "hidden") continue;
    const probe = [attr(i, "name"), attr(i, "id"), attr(i, "placeholder"), attr(i, "autocomplete"), attr(i, "aria-label")].join(" ");
    for (const p of SENSITIVE_FIELD_PATTERNS) if (p.re.test(probe)) found.add(p.label);
  }
  const textAreas = body.match(/<textarea\b[^>]*>/gi) || [];
  for (const ta of textAreas) {
    const probe = [attr(ta, "name"), attr(ta, "id"), attr(ta, "placeholder")].join(" ");
    for (const p of SENSITIVE_FIELD_PATTERNS) if (p.re.test(probe)) found.add(p.label);
  }
  r.sensitiveFields = Array.from(found);

  const iframes = body.match(/<iframe\b[^>]*>/gi) || [];
  for (const f of iframes) {
    const w = attr(f, "width"), h = attr(f, "height"), s = attr(f, "style");
    if (/^[01](px)?$/.test(w) || /^[01](px)?$/.test(h) || /display\s*:\s*none|visibility\s*:\s*hidden|width\s*:\s*[01]px|height\s*:\s*[01]px/i.test(s)) r.hiddenIframes++;
  }
  r.jsRedirect = /(window\.|document\.|top\.)?location(\.href)?\s*=\s*["'`]|location\.(replace|assign)\s*\(/i.test(body);
  r.obfuscatedScript = /eval\s*\(\s*(atob|unescape|String\.fromCharCode)|document\.write\s*\(\s*unescape\s*\(|(\\x[0-9a-f]{2}){20,}/i.test(body);

  const titleLower = r.title.toLowerCase();
  const brandHere = [];
  for (const brand of BRANDS) {
    if (isOfficial(brand, pageReg)) continue;
    for (const tk of brand.tokens) {
      if (tk.length >= 4 && new RegExp("\\b" + tk + "\\b", "i").test(titleLower)) { brandHere.push(brand.name); break; }
    }
  }
  r.brandInTitle = brandHere;
  return r;
}

export function pageIndicators(page, finalUrl) {
  const out = [];
  if (!page.loaded) return out;
  const u = new URL(finalUrl);
  if (page.passwordFields > 0 && u.protocol === "http:") out.push(ind("pw-http", "high", "Asks for a password on an unencrypted page", "A password field was found on a page loaded over plain http. Real sign-in pages are always encrypted.", u.hostname));
  if (page.passwordFields > 0) out.push(ind("pw-form", "info", "Contains a password field", "This page has a sign-in style form. That is normal for real sites too. What matters is whether this is the real site for the service you expect.", page.passwordFields + " password field" + (page.passwordFields > 1 ? "s" : "")));
  if (page.sensitiveFields.length) out.push(ind("sensitive-fields", page.sensitiveFields.some((x) => /recovery phrase|card security|card number/.test(x)) ? "high" : "medium", "The page asks for " + page.sensitiveFields.slice(0, 3).join(", "), "Pages that collect these details are the main target of phishing. Only enter them on a site you reached by typing the address yourself or through the official app.", page.sensitiveFields.join("; ")));
  if (page.crossDomainForms.length) out.push(ind("form-elsewhere", "high", "A form on this page sends what you type to a different website", "Details entered here would be sent to " + Array.from(new Set(page.crossDomainForms)).slice(0, 2).join(", ") + ", not to the site you are looking at.", Array.from(new Set(page.crossDomainForms)).join(", ")));
  if (page.insecureFormActions.length) out.push(ind("form-http", "high", "A form submits over an unencrypted connection", "What you type would be sent without encryption.", Array.from(new Set(page.insecureFormActions)).join(", ")));
  if (page.hiddenIframes) out.push(ind("hidden-iframe", "medium", "Hidden embedded content", page.hiddenIframes + " invisible frame" + (page.hiddenIframes > 1 ? "s were" : " was") + " found. Invisible frames are sometimes used to load other sites without you noticing.", String(page.hiddenIframes)));
  if (page.obfuscatedScript) out.push(ind("obfuscated", "medium", "Scrambled script code", "The page contains code written to be hard to read. Legitimate sites rarely need this.", ""));
  if (page.brandInTitle.length) out.push(ind("brand-in-title", "medium", "Page presents itself as " + page.brandInTitle[0], "The page title mentions " + page.brandInTitle[0] + ", but the domain is not one we have on file for it. Page title: “" + page.title + "”.", page.title));
  if (page.metaRefresh) out.push(ind("meta-refresh", "low", "The page redirects automatically", "The page contains an instruction to move you to another address.", page.metaRefresh));
  else if (page.jsRedirect) out.push(ind("js-redirect", "info", "Script-based redirect code present", "Scripts on the page can send you to another address. This is common on legitimate sites too.", ""));
  return out;
}

// ---------------------------------------------------------------- redirect analysis

export function redirectIndicators(inputParsed, hops, finalUrl) {
  const out = [];
  if (!hops.length) return out;
  const inReg = registrableInfo(inputParsed.host).registrable;
  const finalReg = finalUrl ? registrableInfo(new URL(finalUrl).hostname).registrable : "";
  const wasShortener = SHORTENERS.has(inReg);
  if (finalReg && finalReg !== inReg) {
    out.push(ind("redir-domain", wasShortener ? "low" : "medium", wasShortener ? "The short link leads to " + finalReg : "Redirects to a different domain (" + finalReg + ")", wasShortener ? "Check that " + finalReg + " is where you expected to end up." : "The address you entered sends visitors to a different website. Scam links often start on one domain and end on another.", inReg + " → " + finalReg));
  }
  if (hops.length >= 3) out.push(ind("redir-many", "low", hops.length + " redirects in a row", "Long redirect chains are sometimes used to evade blocklists or hide the final destination.", String(hops.length)));
  if (hops.some((h) => /^http:\/\//i.test(h.location)) && !hops.every((h) => /^http:\/\//i.test(h.url) && /^https:\/\//i.test(h.location))) out.push(ind("redir-http", "low", "A redirect passes through an unencrypted address", "At least one step of the redirect chain used plain http.", ""));
  return out;
}

// ---------------------------------------------------------------- RDAP (domain registration)

export async function fetchRdap(domain) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 6000);
  try {
    const res = await fetch("https://rdap.org/domain/" + encodeURIComponent(domain), { headers: { Accept: "application/rdap+json, application/json" }, signal: controller.signal });
    if (res.status === 404) return { available: false, reason: "The registry did not return a record. Some country registries do not publish registration data this way." };
    if (!res.ok) return { available: false, reason: "The registration lookup service returned an error (" + res.status + ")." };
    const d = await res.json();
    const events = Array.isArray(d.events) ? d.events : [];
    const ev = (a) => { const e = events.find((x) => x && x.eventAction === a); return e && e.eventDate ? e.eventDate : ""; };
    const registeredAt = ev("registration");
    let registrar = "";
    for (const ent of Array.isArray(d.entities) ? d.entities : []) {
      if (Array.isArray(ent.roles) && ent.roles.includes("registrar") && Array.isArray(ent.vcardArray) && Array.isArray(ent.vcardArray[1])) {
        const fn = ent.vcardArray[1].find((x) => x[0] === "fn");
        if (fn && typeof fn[3] === "string") { registrar = fn[3].slice(0, 120); break; }
      }
    }
    // Registrant and contact details are deliberately NOT read or returned.
    const ageDays = registeredAt && !isNaN(Date.parse(registeredAt)) ? Math.floor((Date.now() - Date.parse(registeredAt)) / 86400000) : null;
    return {
      available: true, domain, registeredAt, expiresAt: ev("expiration"), lastChangedAt: ev("last changed"),
      registrar, status: Array.isArray(d.status) ? d.status.slice(0, 6).map(String) : [], ageDays,
    };
  } catch (e) {
    return { available: false, reason: "The registration lookup did not complete in time." };
  } finally {
    clearTimeout(timer);
  }
}

export function domainIndicators(rdap) {
  const out = [];
  if (!rdap || !rdap.available || rdap.ageDays === null) return out;
  if (rdap.ageDays < 0) return out;
  if (rdap.ageDays < 30) out.push(ind("new-domain", "medium", "Domain registered " + (rdap.ageDays === 0 ? "today" : rdap.ageDays + " day" + (rdap.ageDays === 1 ? "" : "s") + " ago"), "Most scam sites are created shortly before they are used. New domains are common for real businesses too, so this is a warning sign, not proof.", rdap.registeredAt.slice(0, 10)));
  else if (rdap.ageDays < 180) out.push(ind("young-domain", "low", "Domain is less than six months old", "Established services usually have older domains. Newer ones deserve a closer look.", rdap.registeredAt.slice(0, 10)));
  return out;
}

// ---------------------------------------------------------------- reputation providers

async function timedFetch(url, init, ms) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), ms || 6000);
  try { return await fetch(url, Object.assign({}, init, { signal: controller.signal })); } finally { clearTimeout(timer); }
}

function b64url(s) {
  const bin = new TextEncoder().encode(s);
  let str = "";
  for (const b of bin) str += String.fromCharCode(b);
  return btoa(str).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

async function checkSafeBrowsing(env, url) {
  const name = "Google Safe Browsing";
  if (!env.GOOGLE_SAFE_BROWSING_KEY) return { provider: name, status: "not_configured", detail: "Not checked: no Google Safe Browsing key is configured on this server." };
  try {
    const res = await timedFetch("https://safebrowsing.googleapis.com/v4/threatMatches:find?key=" + encodeURIComponent(env.GOOGLE_SAFE_BROWSING_KEY), {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        client: { clientId: "scamsense-ai", clientVersion: "1.0" },
        threatInfo: { threatTypes: ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"], platformTypes: ["ANY_PLATFORM"], threatEntryTypes: ["URL"], threatEntries: [{ url }] },
      }),
    }, 6000);
    if (!res.ok) return { provider: name, status: "unavailable", detail: "The service returned an error (" + res.status + ")." };
    const d = await res.json();
    if (d && Array.isArray(d.matches) && d.matches.length) {
      const types = Array.from(new Set(d.matches.map((m) => String(m.threatType || "").replace(/_/g, " ").toLowerCase()))).filter(Boolean);
      return { provider: name, status: "listed", detail: "Listed as dangerous by Google Safe Browsing" + (types.length ? " (" + types.join(", ") + ")" : "") + "." };
    }
    return { provider: name, status: "not_listed", detail: "Not currently on Google's list of dangerous sites. New scam pages are often not listed yet." };
  } catch (e) {
    return { provider: name, status: "unavailable", detail: "The check did not complete in time." };
  }
}

async function checkVirusTotal(env, url) {
  const name = "VirusTotal";
  if (!env.VIRUSTOTAL_API_KEY) return { provider: name, status: "not_configured", detail: "Not checked: no VirusTotal key is configured on this server." };
  try {
    const res = await timedFetch("https://www.virustotal.com/api/v3/urls/" + b64url(url), { headers: { "x-apikey": env.VIRUSTOTAL_API_KEY, Accept: "application/json" } }, 7000);
    if (res.status === 404) return { provider: name, status: "not_listed", detail: "VirusTotal has no existing report for this address. That is not a sign of safety: it may simply never have been scanned." };
    if (res.status === 429) return { provider: name, status: "unavailable", detail: "VirusTotal's request limit was reached. Try again in a minute." };
    if (!res.ok) return { provider: name, status: "unavailable", detail: "The service returned an error (" + res.status + ")." };
    const d = await res.json();
    const st = d && d.data && d.data.attributes && d.data.attributes.last_analysis_stats;
    if (!st) return { provider: name, status: "unavailable", detail: "The report had no analysis results." };
    const total = (st.malicious || 0) + (st.suspicious || 0) + (st.harmless || 0) + (st.undetected || 0);
    const bad = st.malicious || 0, sus = st.suspicious || 0;
    const when = d.data.attributes.last_analysis_date ? new Date(d.data.attributes.last_analysis_date * 1000).toISOString().slice(0, 10) : "";
    const base = bad + " of " + total + " security engines flagged it as malicious and " + sus + " as suspicious" + (when ? " (last analysed " + when + ")" : "") + ".";
    if (bad >= 2) return { provider: name, status: "listed", detail: base };
    if (bad === 1 || sus >= 1) return { provider: name, status: "minor", detail: base + " A single detection can be a false alarm." };
    return { provider: name, status: "not_listed", detail: base };
  } catch (e) {
    return { provider: name, status: "unavailable", detail: "The check did not complete in time." };
  }
}

async function checkUrlhaus(env, url) {
  const name = "URLhaus (abuse.ch)";
  if (!env.URLHAUS_AUTH_KEY) return { provider: name, status: "not_configured", detail: "Not checked: no URLhaus key is configured on this server." };
  try {
    const res = await timedFetch("https://urlhaus-api.abuse.ch/v1/url/", {
      method: "POST", headers: { "Auth-Key": env.URLHAUS_AUTH_KEY, "Content-Type": "application/x-www-form-urlencoded" }, body: "url=" + encodeURIComponent(url),
    }, 6000);
    if (!res.ok) return { provider: name, status: "unavailable", detail: "The service returned an error (" + res.status + ")." };
    const d = await res.json();
    if (d.query_status === "ok") return { provider: name, status: "listed", detail: "Listed in URLhaus as distributing malware" + (d.url_status ? " (status: " + String(d.url_status) + ")" : "") + "." };
    if (d.query_status === "no_results") return { provider: name, status: "not_listed", detail: "Not in the URLhaus malware URL database." };
    return { provider: name, status: "unavailable", detail: "The service gave an unexpected answer." };
  } catch (e) {
    return { provider: name, status: "unavailable", detail: "The check did not complete in time." };
  }
}

// ---------------------------------------------------------------- verdict

const POINTS = { high: 3, medium: 2, low: 1, info: 0 };

export function computeVerdict(indicators, reputation, pageLoaded) {
  const listed = reputation.filter((r) => r.status === "listed");
  const answered = reputation.filter((r) => r.status === "listed" || r.status === "not_listed" || r.status === "minor");
  const points = indicators.reduce((n, i) => n + (POINTS[i.severity] || 0), 0) + reputation.filter((r) => r.status === "minor").length * 2;
  const highs = indicators.filter((i) => i.severity === "high").length;
  if (listed.length) return { level: "known_threat", label: "Reported as dangerous", explanation: "A security database lists this address as harmful (" + listed.map((r) => r.provider).join(", ") + "). Do not enter any details or download anything from it." };
  if (points >= 6 || highs >= 2) return { level: "high_risk", label: "High risk", explanation: "Several strong warning signs point the same way. Treat this address as unsafe unless you can confirm through an official channel that it is genuine." };
  if (points >= 3 || highs >= 1) return { level: "suspicious", label: "Suspicious", explanation: "There are warning signs worth taking seriously. Do not enter passwords, codes or payment details here. Reach the service through its official app or a address you type yourself." };
  if (points >= 1) return { level: "caution", label: "Some warning signs", explanation: "A few minor signs were found. They are not conclusive on their own. Stay careful, especially if this link arrived unexpectedly." };
  if (pageLoaded && answered.length) return { level: "no_issues_found", label: "No issues found in these checks", explanation: "None of the checks that ran found a problem. This is not a guarantee of safety: newly created scam pages are often not in any database yet, and a normal-looking page can still be fraudulent." };
  return { level: "limited", label: "Limited check", explanation: "Not enough could be checked to say much either way. See what was and was not checked below. If you were asked to act urgently, treat that as a warning sign in itself." };
}

// ---------------------------------------------------------------- orchestration

export async function investigateUrl(raw, env) {
  const parsed = parsePublicUrl(raw);
  if (!parsed.ok) return { error: { code: parsed.code, reason: parsed.reason } };

  const info = registrableInfo(parsed.host);
  const normalizedUrl = (() => { const u = new URL(parsed.url.href); u.username = ""; u.password = ""; u.hash = ""; return u.href; })();
  const indicators = staticUrlSignals(parsed);
  const limitations = [
    "ScamSense visited the address once from a server, without logging in. Pages can show different content to different visitors, countries or devices.",
    "The security certificate itself cannot be inspected from this environment. HTTPS only means the connection is encrypted; it does not mean the site is honest.",
  ];

  const canFetch = portAllowed(parsed.port);
  const skipRdap = parsed.isIpLiteral || info.freeHost;
  const [fetched, rdap, gsb, vt, uh] = await Promise.all([
    canFetch ? safeFetch(parsed.url.href) : Promise.resolve({ hops: [], final: null, error: { code: "port", reason: "The address uses a non-standard port, which ScamSense does not contact." } }),
    skipRdap ? Promise.resolve({ available: false, reason: parsed.isIpLiteral ? "Registration data does not apply to a raw IP address." : "The address is hosted on a shared platform (" + info.registrable + "), so the platform's registration date says nothing about this page." }) : fetchRdap(info.registrable),
    checkSafeBrowsing(env, normalizedUrl),
    checkVirusTotal(env, normalizedUrl),
    checkUrlhaus(env, normalizedUrl),
  ]);
  const reputation = [gsb, vt, uh];

  const finalUrl = fetched.final ? fetched.final.url : "";
  indicators.push(...redirectIndicators(parsed, fetched.hops, finalUrl));
  indicators.push(...domainIndicators(rdap));
  for (const r of reputation) if (r.status === "minor") indicators.push(ind("rep-minor-" + r.provider, "medium", r.provider + " reports a possible problem", r.detail, r.provider));

  let page = null;
  if (fetched.final) {
    page = analyzeHtml(fetched.final.body, fetched.final.url);
    indicators.push(...pageIndicators(page, fetched.final.url));
    if (page.loaded && page.textLength < 400) limitations.push("The page shows very little text before scripts run, so form and content checks may be incomplete.");
    if (fetched.final.status >= 400) limitations.push("The site answered with an error (HTTP " + fetched.final.status + "), so its content could not be assessed.");
  }
  if (fetched.error) limitations.push("The page itself could not be loaded: " + fetched.error.reason + " That does not tell us whether the site is safe or unsafe.");
  const notConfigured = reputation.filter((r) => r.status === "not_configured").map((r) => r.provider);
  if (notConfigured.length) limitations.push("Not consulted because they are not set up on this server: " + notConfigured.join(", ") + ".");
  if (!rdap.available) limitations.push("Domain registration details were not available. " + (rdap.reason || ""));

  const pageLoaded = !!(fetched.final && fetched.final.status < 400 && page && page.loaded);
  const verdict = computeVerdict(indicators, reputation, pageLoaded);

  // HTTPS check: never presented as a safety signal.
  const finalHttps = finalUrl.startsWith("https://");
  const hsts = !!(fetched.final && fetched.final.headers["strict-transport-security"]);
  const https = fetched.final
    ? { status: finalHttps ? "note" : "warn", summary: finalHttps ? "The page loaded over an encrypted (https) connection" + (hsts ? " and asks browsers to always use https (HSTS)." : ".") : "The page loaded without encryption (http).", detail: "Encryption protects data in transit. It says nothing about who runs the site: many scam sites use valid https certificates." }
    : { status: "unavailable", summary: "The connection could not be completed.", detail: fetched.error ? fetched.error.reason : "" };

  const sev = (ids) => { const ss = indicators.filter((i) => ids.includes(i.id)); return ss.some((i) => i.severity === "high") ? "risk" : ss.some((i) => i.severity === "medium") ? "warn" : ss.length ? "note" : "ok"; };
  const addressIds = ["userinfo", "ip-host", "punycode", "http", "deep-subdomain", "many-dashes", "risky-tld", "free-host", "shortener", "host-keyword", "port", "long-url", "brand-subdomain", "brand-lookalike", "brand-name"];
  const checks = [
    { id: "address", title: "Address", status: sev(addressIds), summary: indicators.some((i) => addressIds.includes(i.id)) ? "Warning signs in the address itself." : "Nothing unusual in how the address is written." },
    { id: "redirects", title: "Redirects", status: fetched.error && !fetched.hops.length ? "unavailable" : sev(["redir-domain", "redir-many", "redir-http"]), summary: fetched.hops.length ? "The address redirected " + fetched.hops.length + " time" + (fetched.hops.length === 1 ? "" : "s") + (finalUrl ? " and ended at " + new URL(finalUrl).hostname + "." : " before stopping.") : (fetched.final ? "No redirects. The address loaded directly." : "Could not be checked.") },
    { id: "domain", title: "Domain registration", status: rdap.available ? sev(["new-domain", "young-domain"]) : "unavailable", summary: rdap.available ? (rdap.registeredAt ? "Registered " + rdap.registeredAt.slice(0, 10) + (rdap.ageDays !== null ? " (" + rdap.ageDays + " days ago)" : "") + (rdap.registrar ? " through " + rdap.registrar + "." : ".") : "A registry record exists but shows no registration date.") : rdap.reason },
    { id: "https", title: "HTTPS and encryption", status: https.status, summary: https.summary, detail: https.detail },
    { id: "page", title: "Page content", status: page && page.loaded ? sev(["pw-http", "sensitive-fields", "form-elsewhere", "form-http", "hidden-iframe", "obfuscated", "brand-in-title", "meta-refresh"]) : "unavailable", summary: page && page.loaded ? (page.title ? "Page title: “" + page.title + "”. " : "") + page.forms + " form" + (page.forms === 1 ? "" : "s") + " and " + page.passwordFields + " password field" + (page.passwordFields === 1 ? "" : "s") + " found." : "The page content could not be read." },
  ];

  return {
    report: {
      submittedUrl: String(raw).slice(0, 300),
      normalizedUrl,
      host: parsed.host,
      registrableDomain: info.registrable,
      investigatedAt: new Date().toISOString(),
      verdict,
      indicators: indicators.filter((i) => i.severity !== "info").concat(indicators.filter((i) => i.severity === "info")),
      checks,
      redirects: fetched.hops.map((h) => ({ from: h.url, to: h.location, status: h.status })),
      finalUrl,
      finalStatus: fetched.final ? fetched.final.status : null,
      domain: rdap,
      reputation,
      page: page ? { title: page.title, forms: page.forms, passwordFields: page.passwordFields, sensitiveFields: page.sensitiveFields } : null,
      consulted: reputation.filter((r) => r.status !== "not_configured").map((r) => r.provider).concat(rdap.available ? ["RDAP (domain registry)"] : []),
      limitations,
    },
  };
}

// ScamSense AI: Cloudflare Worker backend (worker name: "scamsense-ai")
// POST /   { "message": "...", "history": [ { "role": "user"|"assistant", "content": "..." } ], "system": "..." (optional) }
// ->     { "reply": "..." }       on success
// ->     { "error": "..." }       on any failure (safe, plain message; never contains secrets)
// Secret (set in Cloudflare, never in this file):  env.GEMINI_API_KEY
// Optional plain variable:                         env.GEMINI_MODEL  (defaults to DEFAULT_MODEL below)
// Does only this: receive chat JSON, call Gemini generateContent, return the reply.
// No authentication, storage, or other services.

const ALLOWED_ORIGIN = "https://kingalikid00-sketch.github.io";
const DEFAULT_MODEL = "gemini-3.8-flash";
const GEMINI_BASE = "https://generativelanguage.googleapis.com/v1beta/models/";

const MAX_BODY_CHARS = 200000;   // whole request body
const MAX_TEXT_CHARS = 8000;     // one message
const MAX_SYSTEM_CHARS = 60000;  // app instructions (system)
const MAX_HISTORY_TURNS = 20;    // most recent turns kept
const GEMINI_TIMEOUT_MS = 25000;

function corsHeaders(origin) {
  const h = {
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
    "Access-Control-Max-Age": "86400",
    "Vary": "Origin",
  };
  if (origin === ALLOWED_ORIGIN) h["Access-Control-Allow-Origin"] = ALLOWED_ORIGIN;
  return h;
}

function json(body, status, origin) {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store",
      ...corsHeaders(origin),
    },
  });
}

// Turn the app history into Gemini contents. Accepts {role, content} or {role, text}.
function buildContents(message, history) {
  const contents = [];
  if (Array.isArray(history)) {
    for (const turn of history.slice(-MAX_HISTORY_TURNS)) {
      if (!turn || typeof turn !== "object") continue;
      const raw = typeof turn.content === "string" ? turn.content : turn.text;
      if (typeof raw !== "string") continue;
      const text = raw.trim().slice(0, MAX_TEXT_CHARS);
      if (!text) continue;
      const role = turn.role === "assistant" || turn.role === "model" ? "model" : "user";
      contents.push({ role, parts: [{ text }] });
    }
  }
  while (contents.length && contents[0].role !== "user") contents.shift(); // Gemini needs a user turn first
  contents.push({ role: "user", parts: [{ text: message }] });
  return contents;
}

function extractReply(data) {
  const parts = data && data.candidates && data.candidates[0] && data.candidates[0].content && data.candidates[0].content.parts;
  if (!Array.isArray(parts)) return "";
  return parts.map((p) => (p && typeof p.text === "string" ? p.text : "")).join("").trim();
}

export default {
  async fetch(request, env) {
    const origin = request.headers.get("Origin") || "";
    const url = new URL(request.url);

    // CORS preflight
    if (request.method === "OPTIONS") {
      if (origin && origin !== ALLOWED_ORIGIN) return new Response(null, { status: 403 });
      return new Response(null, { status: 204, headers: corsHeaders(origin) });
    }

    if (url.pathname !== "/") return json({ error: "Not found." }, 404, origin);
    if (request.method !== "POST") return json({ error: "Please use POST." }, 405, origin);

    // Only the ScamSense site may call this from a browser
    if (origin && origin !== ALLOWED_ORIGIN) return json({ error: "This website isn't allowed to use this service." }, 403, origin);

    // Secret check (value is never logged or returned)
    const apiKey = env && env.GEMINI_API_KEY;
    if (!apiKey) {
      console.error("GEMINI_API_KEY is not configured");
      return json({ error: "The AI service isn't set up yet. Please try again later." }, 500, origin);
    }

    // Read and validate the request
    let payload;
    try {
      const raw = await request.text();
      if (raw.length > MAX_BODY_CHARS) return json({ error: "That message is too long." }, 413, origin);
      payload = JSON.parse(raw);
    } catch (e) {
      return json({ error: "That request wasn't valid. Please try again." }, 400, origin);
    }
    if (!payload || typeof payload !== "object" || Array.isArray(payload)) {
      return json({ error: "That request wasn't valid. Please try again." }, 400, origin);
    }
    const message = typeof payload.message === "string" ? payload.message.trim() : "";
    if (!message) return json({ error: "Please type a message first." }, 400, origin);
    if (message.length > MAX_TEXT_CHARS) return json({ error: "That message is too long." }, 413, origin);
    if (payload.history !== undefined && !Array.isArray(payload.history)) {
      return json({ error: "That request wasn't valid. Please try again." }, 400, origin);
    }

    let system = "";
    if (payload.system !== undefined && payload.system !== null) {
      if (typeof payload.system !== "string") {
        return json({ error: "That request wasn't valid. Please try again." }, 400, origin);
      }
      system = payload.system.trim();
      if (system.length > MAX_SYSTEM_CHARS) return json({ error: "That request was too large." }, 413, origin);
    }

    const model = (env.GEMINI_MODEL && /^[A-Za-z0-9._-]+$/.test(env.GEMINI_MODEL)) ? env.GEMINI_MODEL : DEFAULT_MODEL;
    const request_body = { contents: buildContents(message, payload.history) };
    if (system) request_body.systemInstruction = { parts: [{ text: system }] };
    const body = JSON.stringify(request_body);

    // Call Gemini (key goes in a header, never in the URL, never back to the browser)
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), GEMINI_TIMEOUT_MS);
    let res;
    try {
      res = await fetch(GEMINI_BASE + model + ":generateContent", {
        method: "POST",
        headers: { "Content-Type": "application/json", "x-goog-api-key": apiKey },
        body,
        signal: controller.signal,
      });
    } catch (e) {
      clearTimeout(timer);
      const timedOut = e && e.name === "AbortError";
      console.error("Gemini request failed:", timedOut ? "timeout" : "network error");
      return json({ error: timedOut ? "The AI took too long to answer. Please try again." : "I couldn't reach the AI service. Please try again in a moment." }, 504, origin);
    }
    clearTimeout(timer);

    if (!res.ok) {
      console.error("Gemini returned HTTP", res.status);
      if (res.status === 429) return json({ error: "The AI is busy right now. Please try again in a moment." }, 429, origin);
      if (res.status === 400) return json({ error: "The AI couldn't process that request." }, 502, origin);
      if (res.status === 401 || res.status === 403 || res.status === 404) return json({ error: "The AI service isn't set up correctly yet. Please try again later." }, 502, origin);
      return json({ error: "The AI service had a problem. Please try again in a moment." }, 502, origin);
    }

    let data;
    try {
      data = await res.json();
    } catch (e) {
      console.error("Gemini returned an unreadable response");
      return json({ error: "The AI service had a problem. Please try again in a moment." }, 502, origin);
    }

    const reply = extractReply(data);
    if (!reply) {
      const blocked = data && data.promptFeedback && data.promptFeedback.blockReason;
      console.error("Gemini returned no text", blocked ? "(blocked)" : "");
      return json({ error: blocked ? "I can't help with that request." : "The AI didn't return an answer. Please try again." }, 502, origin);
    }

    return json({ reply }, 200, origin);
  },
};

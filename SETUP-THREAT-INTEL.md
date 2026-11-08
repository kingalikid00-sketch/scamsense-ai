# Website Investigator: threat-intelligence setup

The Website Investigator (`POST /connect/investigate-url`) works with no keys. It always runs the address,
redirect, domain-registration (RDAP) and page-content checks. Each key below switches on one more reputation
source. A source without a key is shown in the report as **Not set up**, never as a clean result.

| Secret | Service | Free tier | What it adds |
|---|---|---|---|
| `GOOGLE_SAFE_BROWSING_KEY` | Google Safe Browsing v4 | Free for non-commercial use | Phishing, malware and unwanted-software listings |
| `VIRUSTOTAL_API_KEY` | VirusTotal v3 | Free, rate limited | Existing multi-engine verdicts (lookup only; ScamSense never submits a URL for public scanning) |
| `URLHAUS_AUTH_KEY` | abuse.ch URLhaus | Free key | Malware-distribution URL database |

Add them as Worker secrets (never in the repository or in `index.html`):

```
cd worker
npx wrangler secret put GOOGLE_SAFE_BROWSING_KEY
npx wrangler secret put VIRUSTOTAL_API_KEY
npx wrangler secret put URLHAUS_AUTH_KEY
```

Check the licence terms of each provider before using it commercially.

## Safety properties
- Only public `http`/`https` addresses on ports 80 and 443 are contacted. Private, loopback, link-local, metadata
  and reserved ranges are refused, including IPv4-mapped IPv6, NAT64 and 6to4 forms.
- Every DNS answer is checked (DNS-over-HTTPS) and every redirect hop is re-validated before it is followed.
- GET only; no cookies or credentials; 9 second limit; 512 KB body cap.
- Limit: a Cloudflare Worker cannot pin the IP it connects to, so the DNS check is defence in depth against
  DNS rebinding. Cloudflare's network refuses to connect Workers to private address space.
- The submitted address and any pasted message text are not logged or stored. Only an hourly per-user counter is kept.
- The TLS certificate cannot be inspected from a Worker, so the report says HTTPS only means an encrypted connection.

## Tests
`node --test tools/test-phase-a.mjs` (no network needed).

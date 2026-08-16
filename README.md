# lua-cs-bouncer

> Lua module to allow ip (or not) from CrowdSec API.

:warning: This library will only work with [lua-nginx-module](https://github.com/openresty/lua-nginx-module) 

This library is used by different bouncers : 

* [Nginx Bouncer](https://docs.crowdsec.net/docs/next/bouncers/nginx)
* [OpenResty Bouncer](https://docs.crowdsec.net/docs/next/bouncers/openresty)
* [Ingress Nginx Bouncer](https://docs.crowdsec.net/docs/next/bouncers/ingress-nginx)

## `CAPTCHA_PROVIDER=altcha`

[ALTCHA](https://altcha.org) is a proof-of-work captcha that this bouncer issues and
verifies itself. There is no third-party service to call and no account to hold, so
`SECRET_KEY` and `SITE_KEY` are ignored.

> [!IMPORTANT]
> **Visitors must reach the site over HTTPS to solve the captcha.** The widget
> derives keys with `crypto.subtle`, which browsers expose only in a secure context,
> and it throws `Secure context (HTTPS) required.` before doing any work otherwise.
> The bouncer therefore never serves a captcha to a plain-`http://` request: it
> serves the `CAPTCHA_INSECURE_TEMPLATE_PATH` page instead (the stock one asks the
> visitor to retry over `https://`), or falls back to the ban remediation when that
> page is not configured. Solving the captcha over HTTPS releases the address for
> plain HTTP too.
>
> Two things still count as secure. Terminating TLS at an upstream proxy is fine —
> what matters is the scheme the browser sees, not the one nginx sees, and
> `X-Forwarded-Proto: https` is how the proxy says so. And `http://localhost`,
> `*.localhost`, `http://127.0.0.1` and `http://[::1]` are themselves secure
> contexts, so local development over plain HTTP is served the captcha as normal.

It also needs two things the other providers do not, both outside `crowdsec.conf`:

1. **Two extra rocks**, which is where the key derivation comes from:

   ```
   luarocks install lua-resty-string
   luarocks install lua-resty-openssl
   ```

   Both are pure-Lua FFI bindings and need no build dependencies. They are loaded
   only when `CAPTCHA_PROVIDER=altcha`; if they are missing, altcha refuses to
   configure and the bouncer degrades to `FALLBACK_REMEDIATION`, leaving every other
   provider working.

2. **A dedicated shared dict** in the nginx `http` block:

   ```nginx
   lua_shared_dict crowdsec_altcha 10m;
   ```

   Without it, outstanding challenges fall back to `crowdsec_cache` and compete with
   CrowdSec's own decisions for space. If it is absent, a line is logged at `error`
   level on startup — that is the level to filter on, despite it being advisory.

   Size it generously, because running out is worse than slow. Challenges are keyed by
   client IP and evicted LRU, and an IP whose challenge is evicted has to be issued a
   fresh one — which counts against a per-IP mint ceiling that exists to stop anyone
   turning page reloads into key derivations. Enough eviction inside one 20 minute
   window and that ceiling is reached, at which point the visitor stops being offered a
   captcha and starts being served the ban page instead. Behind NAT or CGNAT, everyone
   on that address shares the outcome.

   Budget about **900 bytes per outstanding challenge**, so the 10m above holds roughly
   **11,500** concurrent ones. That is measured rather than derived from the payload,
   and it is a good deal more than the payload suggests: one challenge is three separate
   dict entries — the JSON, the derived key and the mint counter — and nginx's slab
   allocator rounds each up to a power of two and adds a node header. A 228-byte
   challenge costs about 900 bytes by the time all three are stored.

   In `MODE=stream` there is a second cost: the periodic metrics refresh walks the
   whole key set of `crowdsec_cache` with `get_keys(0)`, which locks the dict. Altcha's
   keys are skipped, but only after being enumerated, so the fallback lengthens a call
   that already blocks the worker.

Tuning (`ALTCHA_COST`, `ALTCHA_COMPLEXITY`, `ALTCHA_ALGORITHM`) is documented inline
in [`config_example.conf`](config_example.conf). Note that the practical ceiling on
the first two is a 60 second solve, not the 90 seconds the widget itself allows:
the bouncer holds the "owes us a captcha" state for 60s from serving the page, and a
solution arriving later is answered with a fresh captcha page rather than a pass.

> [!CAUTION]
> `OVERRIDE_REMEDIATION=captcha` combined with this provider converts ban decisions
> into a proof of work, which is a CPU cost rather than a human-presence test and is
> straightforwardly scriptable — `t/25` does it in about forty lines of Perl with no
> browser. One solve releases the address for the whole of `CAPTCHA_EXPIRATION`. See
> the notes on that setting in [`config_example.conf`](config_example.conf).

### Custom captcha templates

`templates/captcha.html` now renders the widget through `{{captcha_frontend_js_tag}}`
and `{{captcha_widget}}`, because providers disagree on how the widget is loaded and
declared. The previous `{{captcha_frontend_js}}`, `{{captcha_frontend_key}}` and
`{{captcha_site_key}}` are still populated, so templates written against the old
layout keep working with the non-altcha providers — but altcha needs
`{{captcha_widget}}` and will refuse to start without it. Deploy `lib/` and
`templates/` together.

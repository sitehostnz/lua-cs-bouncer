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
`SECRET_KEY` and `SITE_KEY` are ignored. By default one third-party dependency
remains — the widget bundle is fetched from `cdn.jsdelivr.net`, version-pinned with
subresource integrity — and `ALTCHA_WIDGET_FILE`/`ALTCHA_WIDGET_PATH` remove even
that by serving the bundle yourself (see below). Either way, a visitor whose browser
never receives the script is shown an explanatory message by the stock template
rather than a blank form.

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
> Two things still count as secure.
>
> **`set $crowdsec_assume_secure 1;`** in a `server` block. This is how a deployment
> that terminates TLS upstream says so, and it is the **only** way — `X-Forwarded-Proto`
> is deliberately not consulted. nginx records that a trusted proxy is in the request
> path; it does not record who wrote any particular header, so a proxy that sets
> `X-Forwarded-For` but not `X-Forwarded-Proto` (two separate `proxy_set_header` lines,
> so a common half-configuration) passes the visitor's own value straight through, and
> nothing available inside nginx can tell that from the proxy's own assertion. An
> operator assertion is trustworthy where a forwarded header is not. Without
> this, every captcha decision on such a vhost becomes a denial telling an HTTPS
> visitor to retry over HTTPS — and nothing in the log distinguishes that from a
> genuinely plain-HTTP request, because from the bouncer's side the two are
> identical. **If your captcha decisions turn into 403s the moment you enable a
> provider, this is the first thing to check.**
>
> **A loopback origin.** `http://localhost`, `*.localhost`, `http://127.0.0.1` and
> `http://[::1]` are themselves secure contexts, so local development over plain
> HTTP is served the captcha as normal — provided the request also arrives from a
> loopback address, since the `Host` header alone is the client's to choose. If nginx
> runs in a container and the browser is on the host, the request arrives from the
> bridge gateway instead: use `$crowdsec_assume_secure` in that vhost.

It also needs two things the other providers do not, both outside `crowdsec.conf`:

1. **Two extra rocks**, which is where the key derivation comes from:

   ```
   luarocks install lua-resty-string 0.09-0
   luarocks install lua-resty-openssl 1.8.0-1
   ```

   Those are the versions CI exercises, and the only ones this code is tested
   against. Pin them. `lua-resty-openssl` is an FFI binding whose API tracks the
   OpenSSL it was built for, and `altcha.lua` reaches into `resty.openssl.kdf` and
   `resty.openssl.digest` directly — a release that reshapes either turns every
   captcha decision into `FALLBACK_REMEDIATION` with one line in the startup log, and
   one that removes a function stops nginx starting outright. This repository is
   consumed by commit pin, so its Lua is frozen while unpinned rocks are not.

   Both are pure-Lua FFI bindings and need no build dependencies. They are loaded
   only when `CAPTCHA_PROVIDER=altcha`; if they are missing, altcha refuses to
   configure and the bouncer degrades to `FALLBACK_REMEDIATION`, leaving every other
   provider working.

2. **A dedicated shared dict** in the nginx `http` block:

   ```nginx
   lua_shared_dict crowdsec_altcha 10m;
   ```

   Without it, altcha refuses to configure and the bouncer degrades to
   `FALLBACK_REMEDIATION` — refused rather than shared, because challenges are
   attacker-paced writes, and letting them fall back into `crowdsec_cache` would let
   a rotating source evict the decision cache the bouncer exists to enforce.

   Size it generously, because running out is worse than slow. Challenges are keyed by
   client IP and evicted LRU, and an IP whose challenge is evicted has to be issued a
   fresh one — which counts against a per-IP mint ceiling that exists to stop anyone
   turning page reloads into key derivations. Enough eviction inside one 20 minute
   window and that ceiling is reached, at which point the visitor stops being offered a
   captcha and starts being served the ban page instead. Behind NAT or CGNAT, everyone
   on that address shares the outcome.

   Budget about **800 bytes per outstanding challenge**, so the 10m above holds roughly
   **13,000** concurrent ones. That is more than the payload suggests: one challenge is
   two dict entries — the JSON with its redeeming key prepended, and the mint counter —
   and nginx's slab allocator rounds each up to a power of two and adds a node header,
   so a ~300-byte challenge entry occupies a 512-byte slab before the counter is even
   stored.

Tuning (`ALTCHA_COST`, `ALTCHA_COMPLEXITY`, `ALTCHA_ALGORITHM`) is documented inline
in [`config_example.conf`](config_example.conf). The practical ceiling on the first
two is the widget's own 90 second solve timeout: the bouncer holds the "owes us a
captcha" state for five minutes from serving the page, and solving starts as the
page paints, so the widget gives up well before the bouncer does.

> [!CAUTION]
> `OVERRIDE_REMEDIATION=captcha` combined with this provider converts ban decisions
> into a proof of work, which is a CPU cost rather than a human-presence test and is
> straightforwardly scriptable — `t/25` does it in about forty lines of Perl with no
> browser. One solve releases the address for the whole of `CAPTCHA_EXPIRATION`. See
> the notes on that setting in [`config_example.conf`](config_example.conf).
>
> It also leaves `/favicon.ico` reachable for banned addresses: captcha decisions
> have always exempted that path (the captcha page's own favicon request would
> otherwise overwrite the address the visitor is released to), and the override
> turns ban decisions into captcha decisions. Keep `/favicon.ico` a static file.

### Self-hosting the widget

```
ALTCHA_WIDGET_FILE=/var/lib/crowdsec/lua/assets/altcha-3.2.1.js
ALTCHA_WIDGET_PATH=/.crowdsec/altcha-3.2.1.js
```

Set both and the bouncer reads the bundle once at startup and serves it from that
path itself, with a year of immutable caching; the captcha page's script tag then
points there instead of at the CDN, without an `integrity` attribute — a page served
from your own origin has no third party left to distrust, and a stale hash would fail
silently. Set one without the other, or name a file that cannot be read, and the pair
is ignored with a line in the log and the CDN copy is used instead.

Verify the bundle where you fetch it (a checksum in your image build, say) rather
than in the browser, and put the version in the path so a new bundle arrives under a
new URL.

The bundle goes out as `application/javascript`, which is **not** in nginx's default
`gzip_types` — that default is `text/html` alone. Add it there if you want the
response compressed; the bouncer sets `Content-Length` and leaves the encoding to
nginx rather than holding a second, compressed copy.

The bundle is served from the access phase, before any remediation runs. That is
what makes it work on **every vhost with no location block**, and it is also
required rather than merely convenient: the script is fetched by an address that is
being captcha'd, so any other handling would answer it with the captcha page —
arriving as HTML where the browser expects a module, and rewriting the URI the
visitor is released to, so solving would drop them on the `.js` file instead of the
page they asked for. No `EXCLUDE_LOCATION` entry is needed.

### Custom captcha templates

`templates/captcha.html` now renders the widget through `{{captcha_frontend_js_tag}}`
and `{{captcha_widget}}`, because providers disagree on how the widget is loaded and
declared. The previous `{{captcha_frontend_js}}`, `{{captcha_frontend_key}}` and
`{{captcha_site_key}}` are still populated, so templates written against the old
layout keep working with the non-altcha providers — but altcha needs
`{{captcha_widget}}` and will refuse to start without it. Deploy `lib/` and
`templates/` together.

# Changelog

All notable changes to this project will be documented in this file.

This project is a fork of
[crowdsecurity/lua-cs-bouncer](https://github.com/crowdsecurity/lua-cs-bouncer);
entries describe the fork's changes relative to upstream.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [2026.08.26-v1.0.17]

### Added

- `ALTCHA_MINTS_PER_SECOND` replaces the calibrated altcha mint budget with a stated
  rate per worker, for hosts whose real CPU limit the calibration cannot see. (#2)

## [2026.08.24-v1.0.16]

### Added

- `$crowdsec_ban_template`, `$crowdsec_captcha_template` and
  `$crowdsec_captcha_insecure_template` let a `server` block serve its own pages,
  following the `$crowdsec_enable_bouncer` pattern. An unset variable or a missing file
  falls back to the global template, and pages are read per serve so edits apply without
  a reload. (#3)
- A per-vhost captcha override that does not carry exactly one `{{captcha_widget}}` slot
  degrades to the stock captcha page, rather than serving a widget nobody can solve. (#3)
- Override paths containing `..` are refused, so a config that interpolates request data
  into the path cannot be steered into a traversal. (#3)
- `CAPTCHA_PROVIDER=altcha`: a self-verifying [ALTCHA](https://altcha.org) proof-of-work
  captcha the bouncer issues and checks itself, with no third-party service or account.
  Tuned with `ALTCHA_COST`, `ALTCHA_COMPLEXITY` and `ALTCHA_ALGORITHM`. Needs the
  `lua-resty-string` and `lua-resty-openssl` rocks and a `crowdsec_altcha` shared dict;
  without them it refuses to configure and degrades to `FALLBACK_REMEDIATION`. The widget
  solves on page load, and requires the visitor to reach the site over HTTPS. (#2)
- `ALTCHA_WIDGET_FILE` and `ALTCHA_WIDGET_PATH` serve the altcha widget from the bouncer
  instead of jsdelivr, removing the provider's last third-party dependency. Setting only
  one, or naming an unreadable file, falls back to the CDN. (#2)
- Altcha minting is bounded in aggregate as well as per address: 50 ms of key derivation
  per worker per second, calibrated at startup so it tracks `ALTCHA_COST` with no new
  setting. Over budget, a challenge is refused and the decision degrades to
  `FALLBACK_REMEDIATION`; a challenge the visitor already holds is never refused. (#2)
- `OVERRIDE_REMEDIATION` forces every bounced decision to one remediation, whatever type
  the LAPI or the appsec component returned. (#2)
- `CAPTCHA_INSECURE_TEMPLATE_PATH` names a page to serve when a captcha decision arrives
  over plain HTTP, where the widget cannot run. Unset, those decisions become a ban. (#2)
- `$crowdsec_assume_secure` nginx variable (`set $crowdsec_assume_secure 1;` in a `server`
  block) asserts that a vhost is reached over HTTPS, for deployments terminating TLS
  upstream. (#2)
- Template placeholders `{{captcha_frontend_js_tag}}` and `{{captcha_widget}}`, so a
  captcha template can carry the provider's script tag and widget markup. (#2)
- A solved captcha is logged, with how long the address is released for. (#2)

### Changed

- Captcha decisions arriving over plain HTTP are no longer served a captcha, for every
  provider: the widget needs a secure browser context. They get
  `CAPTCHA_INSECURE_TEMPLATE_PATH`, or a ban if it is unset. (#2)
- `X-Forwarded-Proto` is no longer consulted when deciding whether the browser is in a
  secure context — nothing can tell a header a trusted proxy set from one a client sent.
  Use `$crowdsec_assume_secure` instead. (#2)
- The captcha verify window is 300 s, up from 60 s, so a slow solve is not rejected. (#2)
- `captcha.apply()` takes `(remote_ip, ret_code)`. Callers on the old no-argument form
  still work. (#2)
- The altcha widget no longer shows its "Protected by ALTCHA" footer. (#2)
- An empty `CAPTCHA_PROVIDER=` line is reported once at startup rather than per request.
  (#2)

### Fixed

- The URI a solved visitor is redirected to is no longer taken from the `Referer` header,
  which was used verbatim as the `Location` — a crafted `Referer` redirected the visitor
  off-site the moment they passed the check. It is now the path of the GET that opened the
  flow, and is rejected unless it is a single-slash absolute path with no control
  characters and at most 512 bytes. (#2)
- A failed captcha attempt no longer overwrites where the visitor is released to. (#2)
- `FALLBACK_REMEDIATION=captcha` with no usable captcha provider is reconciled to `ban` at
  startup. It previously let every denied request through. (#2)
- `FALLBACK_REMEDIATION` defaults to `ban` when the setting is absent, rather than
  allowing the request. (#2)
- Template placeholder values are escaped before substitution, so a `%` in `SITE_KEY` or
  any other interpolated setting can no longer abort `init_by_lua` and stop nginx
  starting. (#2)
- Captcha form fields that are not strings — submitted twice, or with no value — are
  rejected instead of raising. (#2)
- An unsupported `CAPTCHA_PROVIDER` is rejected at startup, degrading to
  `FALLBACK_REMEDIATION` instead of serving an unusable page. (#2)
- A non-numeric value for an integer setting is reported in the error log instead of
  being silently treated as zero. (#2)

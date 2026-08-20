# Changelog

All notable changes to this project will be documented in this file.

This project is a fork of
[crowdsecurity/lua-cs-bouncer](https://github.com/crowdsecurity/lua-cs-bouncer);
entries describe the fork's changes relative to upstream.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added

- New `altcha` captcha provider (`CAPTCHA_PROVIDER=altcha`): a self-verifying
  [ALTCHA](https://altcha.org) proof-of-work captcha that the bouncer issues and checks
  itself, with no third-party service or account (`SITE_KEY` and `SECRET_KEY` are
  unused). It is tuned through the new `ALTCHA_COST`, `ALTCHA_COMPLEXITY` and
  `ALTCHA_ALGORITHM` settings, and requires the `lua-resty-string` and
  `lua-resty-openssl` rocks plus a dedicated `crowdsec_altcha` shared dict — without
  either it refuses to configure and degrades to `FALLBACK_REMEDIATION`, so challenge
  churn can never evict CrowdSec's own decision cache. The widget is pinned to
  `altcha@3.2.1` with subresource integrity and fetched from jsdelivr by default (see
  `ALTCHA_WIDGET_FILE` below to serve it yourself) — a visitor whose browser never
  receives the script is shown an explanatory message rather than a blank form — and
  solves automatically as the page loads, with no click needed. Visitors must reach
  the site over HTTPS. If a challenge cannot be issued, the visitor is served the ban
  page rather than an unsolvable captcha. (#2)
- New `ALTCHA_WIDGET_FILE` and `ALTCHA_WIDGET_PATH` settings serve the altcha widget
  bundle from the bouncer itself instead of jsdelivr, removing the provider's last
  third-party dependency: a visitor who cannot reach the CDN was otherwise served a
  captcha with no widget on it. The bundle is read once at startup and answered from
  the access phase, so it covers every vhost with no location block and is never
  bounced — a captcha'd address fetching the script would otherwise receive the
  captcha page, and be released to the script rather than to the page it asked for.
  Setting only one of the two, or naming an unreadable file, logs and falls back to
  the CDN. (#2)
- New template placeholders `{{captcha_frontend_js_tag}}` and `{{captcha_widget}}`,
  used by the stock `templates/captcha.html`. The previous placeholders are still
  populated, so custom templates keep working with the existing providers; altcha
  requires `{{captcha_widget}}`. (#2)
- New `OVERRIDE_REMEDIATION` setting that forces every bounced decision to `captcha`
  or `ban`, whatever remediation the LAPI or the appsec component returned. Forcing
  captcha while the captcha provider is misconfigured still degrades to
  `FALLBACK_REMEDIATION`. (#2)
- A solved captcha is now logged, including how long the address is released for;
  previously only failed attempts were logged. (#2)
- Captcha decisions that arrive over plain HTTP are no longer served a widget the
  browser cannot run: the bouncer serves the page named by the new
  `CAPTCHA_INSECURE_TEMPLATE_PATH` setting (denied with the same status a ban would
  carry; the stock `templates/captcha_insecure.html` asks the visitor to retry over
  `https://`), or falls back to the ban remediation when the page is not configured.
  Requests with `X-Forwarded-Proto: https` and localhost/loopback origins count as
  secure contexts and are served the captcha as normal. (#2)

### Changed

- `captcha.apply()` now takes `(remote_ip, ret_code)`; callers on the old
  zero-argument form keep working, as a nil `remote_ip` falls back to the request
  address. (#2)
- The captcha verify window (between serving the page and accepting the solution)
  is now 300 seconds rather than 60; with the widget solving on page load, the
  widget's own 90 second timeout is the practical ceiling. (#2)
- An empty `CAPTCHA_PROVIDER=` line is reported once at startup as "captcha not
  configured" at notice level, rather than as an unsupported-provider error. (#2)
- Serving the insecure-context page is logged at info level rather than error;
  error is reserved for the case where no page is configured and a ban is served
  instead. (#2)

### Fixed

- The captcha-usability flag now lives in module state rather than the shared dict,
  so it can no longer be evicted; previously an evicted flag let bounced requests
  through, and once that was hardened to fail closed, an eviction silently converted
  captcha to ban until reload. (#2)
- Two concurrent first requests from one IP no longer mint two altcha challenges
  with the second invalidating the first; the losing request now serves the winning
  challenge. A challenge and the key that redeems it are stored as one atomic dict
  entry, so no partial or mismatched state can exist. (#2)
- `OVERRIDE_REMEDIATION` now logs when it discards an appsec challenge response
  (body, headers and cookies) instead of dropping it silently. (#2)
- `FALLBACK_REMEDIATION` now defaults to `ban` when the line is absent from the
  configuration; previously an absent line let the request through whenever the
  fallback path was taken. (#2)
- Captcha form fields that are not strings (submitted twice, or with no value) are
  refused as a failed captcha instead of raising an HTTP 500. (#2)
- An unsupported `CAPTCHA_PROVIDER` is now rejected when the bouncer starts, degrading
  to `FALLBACK_REMEDIATION`, instead of failing on each request. (#2)
- A non-numeric value for an integer setting is now reported in the error log instead
  of being silently ignored. (#2)

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
  `ALTCHA_ALGORITHM` settings, requires the `lua-resty-string` and `lua-resty-openssl`
  rocks, and optionally uses a dedicated `crowdsec_altcha` shared dict (without one,
  challenges share `crowdsec_cache` with CrowdSec's own decisions). The widget is
  pinned to `altcha@3.2.1` with subresource integrity, and visitors must reach the
  site over HTTPS. If a challenge cannot be issued, the visitor is served the ban page
  rather than an unsolvable captcha. (#2)
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
- Per-vhost template overrides: a server block can point the bouncer at its own
  pages with `set $crowdsec_ban_template <path>;`, `set $crowdsec_captcha_template
  <path>;` and `set $crowdsec_captcha_insecure_template <path>;`, following the
  `$crowdsec_enable_bouncer` pattern. An unset variable or a missing file falls back
  to the global template, files are read per serve so page edits apply without a
  reload, and a captcha override without a `{{captcha_widget}}` slot degrades to the
  stock captcha page rather than serving a widget nobody can solve. Override paths
  containing `..` are refused, so a config that interpolates request data into the
  path cannot be steered into a traversal. (#3)

### Fixed

- A missing `captcha_ok` flag (for example, evicted from the shared dict under
  pressure) now degrades captcha decisions to `FALLBACK_REMEDIATION` instead of
  letting the request through. (#2)
- `FALLBACK_REMEDIATION` now defaults to `ban` when the line is absent from the
  configuration; previously an absent line let the request through whenever the
  fallback path was taken. (#2)
- Captcha form fields that are not strings (submitted twice, or with no value) are
  refused as a failed captcha instead of raising an HTTP 500. (#2)
- An unsupported `CAPTCHA_PROVIDER` is now rejected when the bouncer starts, degrading
  to `FALLBACK_REMEDIATION`, instead of failing on each request. (#2)
- A non-numeric value for an integer setting is now reported in the error log instead
  of being silently ignored. (#2)

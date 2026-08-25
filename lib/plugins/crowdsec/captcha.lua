local http = require "resty.http"
local cjson = require "cjson"
local template = require "plugins.crowdsec.template"
local utils = require "plugins.crowdsec.utils"
local ban = require "plugins.crowdsec.ban"

-- Loaded in M.New(), and only for CAPTCHA_PROVIDER=altcha. It pulls in
-- lua-resty-openssl and lua-resty-string, which nothing else here needs and which a
-- stock nginx + lua-nginx-module install does not ship. Requiring it at module scope
-- would make those rocks a hard dependency of the whole bouncer: this file is
-- reached from crowdsec.lua on every configuration, so a missing rock would raise
-- out of init_by_lua and stop nginx starting even for recaptcha or no captcha at all.
local altcha

local M = {_TYPE='module', _NAME='recaptcha.funcs', _VERSION='1.0-0'}

local captcha_backend_url = {}
captcha_backend_url["recaptcha"] = "https://www.recaptcha.net/recaptcha/api/siteverify"
captcha_backend_url["hcaptcha"] = "https://hcaptcha.com/siteverify"
captcha_backend_url["turnstile"] = "https://challenges.cloudflare.com/turnstile/v0/siteverify"
-- altcha has no backend to call: challenges are issued and verified in-process

local captcha_frontend_js = {}
captcha_frontend_js["recaptcha"] = "https://www.recaptcha.net/recaptcha/api.js"
captcha_frontend_js["hcaptcha"] = "https://js.hcaptcha.com/1/api.js"
captcha_frontend_js["turnstile"] = "https://challenges.cloudflare.com/turnstile/v0/api.js"
-- pinned rather than tracking latest: the widget is the one part of this that a
-- CDN serves to a visitor we have already decided is suspect
captcha_frontend_js["altcha"] = "https://cdn.jsdelivr.net/npm/altcha@3.2.1/dist/main/altcha.js"

-- Pinning says which bundle we asked for; this says we got it. Without it a
-- compromised or coerced CDN can run whatever it likes on a page we serve from our
-- own origin, which is a poor property for a security control. sha256 of
-- dist/main/altcha.js at 3.2.1. It is a pair with the URL above - bump one and the
-- other has to move with it, or the widget silently fails to load.
--
-- A third thing moves with them and lives in the other module: ALGORITHMS in
-- altcha.lua is the set this exact bundle registers a solver for. Bumping the
-- version means checking all three, and only two of them are in this file.
local captcha_frontend_js_integrity = {}
captcha_frontend_js_integrity["altcha"] = "sha256-CzPTjutlEjfukCQYlXjqZEvarRpqKbsRfmvOmGXqSIg="

local captcha_frontend_key = {}
captcha_frontend_key["recaptcha"] = "g-recaptcha"
captcha_frontend_key["hcaptcha"] = "h-captcha"
captcha_frontend_key["turnstile"] = "cf-turnstile"
-- yields the "altcha-response" form field name via M.GetCaptchaBackendKey()
captcha_frontend_key["altcha"] = "altcha"

-- Marks where a per-visitor altcha challenge is spliced into the rendered page.
-- Anything unique to this file will do; it never reaches the browser.
local ALTCHA_CHALLENGE_PLACEHOLDER = "__CROWDSEC_ALTCHA_CHALLENGE__"

-- Splits a compiled page around the challenge slot. Returns head and tail, or
-- nils and a reason (a phrase that reads with a path or 'it' after it) when the
-- page does not carry exactly one widget. Shared by M.New(), which refuses to
-- start on a bad stock template, and by the per-vhost path in M.apply(), which
-- falls back to the stock page instead - a request is not the place to take the
-- captcha down.
local function split_altcha_view(view)
    local at = view:find(ALTCHA_CHALLENGE_PLACEHOLDER, 1, true)
    if at == nil then
        return nil, nil, "renders no altcha widget, add {{captcha_widget}} to"
    end
    -- Splitting at the first hit leaves any later one verbatim in the tail, so a
    -- second widget reaches the browser with the placeholder still in its
    -- challenge attribute. That does not start with '{', so the widget reads it
    -- as a URL to fetch a challenge from and errors on a path that does not
    -- exist - and the duplicate id makes the verified listener bind to whichever
    -- element parses first. Nothing about that is diagnosable from the page, so
    -- refuse instead.
    if view:find(ALTCHA_CHALLENGE_PLACEHOLDER, at + #ALTCHA_CHALLENGE_PLACEHOLDER, true) ~= nil then
        return nil, nil, "renders more than one altcha widget, leave a single {{captcha_widget}} in"
    end
    return view:sub(1, at - 1), view:sub(at + #ALTCHA_CHALLENGE_PLACEHOLDER)
end

-- Per-worker latch for the upgrade hint below. Module state, so it resets on reload,
-- which is when an operator is most likely to want it again.
local forwarded_proto_hint_logged = false

M.SecretKey = ""
M.SiteKey = ""
M.Template = ""
M.InsecureTemplate = ""
M.ret_code = ngx.HTTP_OK
-- Set together, or not at all: the URL path the widget bundle is served at, and
-- the bundle itself, held in memory from init. See the widget block in M.New().
M.WidgetPath = ""
M.WidgetBody = ""

-- Provider variance is expressed two ways in this file, on purpose. The tables
-- above carry per-provider values; anything that is not a value - altcha is
-- self-verifying, needs no key pair, mints a challenge per visitor and declares its
-- widget differently - is an inline `M.CaptchaProvider == "altcha"` branch rather
-- than a trait table or a provider module.
--
-- That is a fork decision, not an oversight. This repository tracks upstream, and
-- additive branches conflict rarely where a provider-interface refactor would
-- conflict on every upstream change to this file. The same reasoning applies to the
-- positional parameter list below: several downstream bouncers call M.New() and
-- M.apply() themselves, so the signature is append-only and the back-compat shim in
-- M.apply() exists for callers still on the pre-altcha form.
--
-- Both are worth revisiting the day this stops tracking upstream, and not before.
function M.New(siteKey, secretKey, TemplateFilePath, captcha_provider, ret_code, altcha_cost, altcha_algorithm, altcha_complexity, insecure_template_path, widget_file, widget_path, altcha_mints_per_second)

    M.CaptchaProvider = captcha_provider

    -- the provider drives every lookup below, so reject an unknown one here rather
    -- than letting it surface as a nil concatenation while rendering the template
    if captcha_frontend_key[M.CaptchaProvider] == nil then
      return "unsupported captcha provider '" .. tostring(captcha_provider) .. "'"
    end

    -- altcha mints and checks its own challenges, so there is no account to hold
    -- with anyone and no key pair to configure
    if M.CaptchaProvider ~= "altcha" then
      if siteKey == nil or siteKey == "" then
        return "no recaptcha site key provided, can't use recaptcha"
      end

      if secretKey == nil or secretKey == "" then
        return "no recaptcha secret key provided, can't use recaptcha"
      end
    end

    M.SiteKey = siteKey or ""
    M.SecretKey = secretKey or ""

    if TemplateFilePath == nil then
      return "CAPTCHA_TEMPLATE_PATH variable is empty, will ban without template"
    end
    if utils.file_exist(TemplateFilePath) == false then
      return "captcha template file doesn't exist, can't use recaptcha"
    end

    local captcha_template = utils.read_file(TemplateFilePath)
    if captcha_template == nil then
        return "Template file " .. TemplateFilePath .. "not found."
    end

    if M.CaptchaProvider == "altcha" then
      -- pcall so a missing rock comes back as a captcha.New() error string, which
      -- leaves captcha_ok false and degrades to FALLBACK_REMEDIATION, rather than
      -- raising out of init_by_lua and refusing to start nginx
      local loaded, mod = pcall(require, "plugins.crowdsec.altcha")
      if not loaded then
        return "captcha provider 'altcha' needs the lua-resty-openssl and " ..
          "lua-resty-string rocks: " .. tostring(mod)
      end
      altcha = mod

      local err = altcha.New(altcha_cost, altcha_algorithm, altcha_complexity, altcha_mints_per_second)
      if err ~= nil then
        return err
      end
    end

    -- Optional self-hosted widget bundle, which removes the only third party left
    -- in this provider: by default the browser fetches altcha.js from a CDN, and a
    -- visitor whose network cannot reach it is served a captcha with no widget.
    -- Held in memory and answered from M.ServeWidget() rather than by a location
    -- block, so one http-level access_by_lua_block covers every vhost.
    --
    -- Both keys or neither. The path is what the script tag advertises and what
    -- ServeWidget() answers, so one without the other either points the browser at
    -- a URL nothing serves, or serves a URL nothing asks for.
    --
    -- Unusable is reported and falls back to the CDN rather than failing the
    -- provider: a visitor who can reach jsdelivr is better off than one served a
    -- captcha page with no widget on it at all.
    M.WidgetPath = ""
    M.WidgetBody = ""
    local widget_wanted = (widget_file ~= nil and widget_file ~= "") or
                          (widget_path ~= nil and widget_path ~= "")
    if M.CaptchaProvider == "altcha" and widget_wanted then
        if widget_file == nil or widget_file == "" or widget_path == nil or widget_path == "" then
            ngx.log(ngx.ERR, "ALTCHA_WIDGET_FILE and ALTCHA_WIDGET_PATH must be set together, " ..
                "serving the widget from the CDN instead")
        elseif utils.starts_with(widget_path, "/") == false then
            -- compared against ngx.var.uri, which is always absolute, so a
            -- relative path here would simply never match
            ngx.log(ngx.ERR, "ALTCHA_WIDGET_PATH '" .. widget_path .. "' must start with '/', " ..
                "serving the widget from the CDN instead")
        elseif widget_path:find("[%%?#]") ~= nil then
            -- The path is interpolated into the script tag below, and that string
            -- goes through template.compile(), where this value lands in the
            -- replacement position of a gsub. Lua reads '%' there as a capture
            -- reference, so anything other than '%%' raises - out of init_by_lua,
            -- which stops nginx starting for every vhost rather than degrading this
            -- one provider. Every other unusable widget configuration in this block
            -- logs and falls back, and this was the one path that did not.
            --
            -- Such a path is only reachable double-encoded, which is reason enough to
            -- refuse it. ServeWidget() compares against ngx.var.uri, and nginx decodes
            -- that, so '%25' arrives as '%' and a request for
            -- '/x/altcha%2520test.js' does match a configured '/x/altcha%20test.js' -
            -- measured. '?' and '#' behave the same way via '%3F' and '%23'. So the
            -- path is matchable, just not by anything a visitor would type, and the
            -- init-time raise is now prevented in template.compile() as well.
            ngx.log(ngx.ERR, "ALTCHA_WIDGET_PATH '" .. widget_path ..
                "' must not contain '%', '?' or '#', serving the widget from the CDN instead")
        else
            local body = utils.read_file_bytes(widget_file)
            if body == nil or body == "" then
                ngx.log(ngx.ERR, "ALTCHA_WIDGET_FILE '" .. widget_file .. "' cannot be read, " ..
                    "serving the widget from the CDN instead")
            else
                M.WidgetPath = widget_path
                M.WidgetBody = body
                ngx.log(ngx.NOTICE, "serving the altcha widget from '" .. widget_path ..
                    "' (" .. #body .. " bytes), not from the CDN")
            end
        end
    end

    local ret_code_ok = false
    if ret_code ~= nil and ret_code ~= 0 and ret_code ~= "" then
        for k, v in pairs(utils.HTTP_CODE) do
            if k == ret_code then
                M.ret_code = utils.HTTP_CODE[ret_code]
                ret_code_ok = true
                break
            end
        end
        if ret_code_ok == false then
            ngx.log(ngx.ERR, "CAPTCHA_RET_CODE '" .. ret_code .. "' is not supported, using default HTTP code " .. M.ret_code)
        end
    end

    -- Optional standalone page for captcha decisions that arrive over plain HTTP,
    -- where the widget cannot run (see the secure-context gate in M.apply()). Loaded
    -- raw rather than through the template engine: nothing per-provider belongs on
    -- it, so there are no placeholders to fill. Unreadable is reported but does not
    -- fail the provider - the page is a courtesy on top of the ban fallback, and
    -- losing captcha over HTTPS to a typo here would be the worse trade.
    M.InsecureTemplate = ""
    if insecure_template_path ~= nil and insecure_template_path ~= "" then
        if utils.file_exist(insecure_template_path) == true then
            M.InsecureTemplate = utils.read_file(insecure_template_path) or ""
        end
        if M.InsecureTemplate == "" then
            ngx.log(ngx.ERR, "CAPTCHA_INSECURE_TEMPLATE_PATH '" .. insecure_template_path ..
                "' cannot be read, captcha decisions over plain HTTP will be served a ban instead")
        end
    end

    local template_data = {}
    -- still exported so templates written against the previous layout keep rendering
    template_data["captcha_site_key"] =  M.SiteKey
    template_data["captcha_frontend_js"] = captcha_frontend_js[M.CaptchaProvider]
    template_data["captcha_frontend_key"] = captcha_frontend_key[M.CaptchaProvider]

    -- providers disagree on how the widget is loaded and declared, and the template
    -- engine has no conditionals, so the markup is rendered here and injected whole
    if M.CaptchaProvider == "altcha" then
        if M.WidgetPath ~= "" then
            -- No integrity and no crossorigin: the bundle comes from this origin
            -- now, so there is no third party to distrust, and the file is verified
            -- where it is fetched rather than in the browser. A hash pinned here
            -- would also have to match whatever the operator deployed, and a
            -- mismatch fails silently - the element never upgrades.
            template_data["captcha_frontend_js_tag"] =
                '<script async defer type="module" src="' .. M.WidgetPath .. '"></script>'
        else
            template_data["captcha_frontend_js_tag"] =
                '<script async defer type="module" src="' .. captcha_frontend_js["altcha"] ..
                '" integrity="' .. captcha_frontend_js_integrity["altcha"] ..
                '" crossorigin="anonymous"></script>'
        end
        -- auto="onload", so solving starts as the page paints instead of waiting
        -- for a click. The bouncer only holds the verify state for CAPTCHA_VERIFY_TTL
        -- from serving the page, and the click was never a bot barrier - the proof of work is
        -- the gate, and t/25 pays it with no browser at all - so a click bought no
        -- security and spent the visitor's solve window on noticing a button.
        -- The challenge itself is per-visitor, so a placeholder stands in here and
        -- M.apply() splices the visitor's own in.
        template_data["captcha_widget"] =
            '<altcha-widget id="captcha" name="' .. M.GetCaptchaBackendKey() ..
            '" challenge=\'' .. ALTCHA_CHALLENGE_PLACEHOLDER ..
            -- hideFooter drops the widget's "Protected by ALTCHA" credit. It is not a
            -- bare attribute: the element observes only auto, challenge, configuration,
            -- display, language, name, theme, type and workers, and everything else
            -- arrives as JSON through `configuration`, which the widget JSON.parses and
            -- Object.assigns over its defaults - so naming one key leaves the rest alone.
            '\' auto="onload" configuration=\'{"hideFooter":true}\'></altcha-widget>' ..
            -- wrapped in a function so captchaCallback resolves when the event fires
            -- rather than while this script is parsed: it is declared further down
            '<script>document.getElementById("captcha")' ..
            '.addEventListener("verified", function () { captchaCallback() })</script>'
    else
        template_data["captcha_frontend_js_tag"] =
            '<script src="' .. captcha_frontend_js[M.CaptchaProvider] .. '" async defer></script>'
        template_data["captcha_widget"] =
            '<div id="captcha" class="' .. captcha_frontend_key[M.CaptchaProvider] ..
            '" data-sitekey="' .. M.SiteKey .. '" data-callback="captchaCallback"></div>'
    end

    -- kept for the per-vhost path in M.apply(), which compiles a host's own page
    -- with these same substitutions at serve time
    M.TemplateData = template_data

    local view = template.compile(captcha_template, template_data)

    -- template.compile() iterates the data, not the template, so a placeholder with
    -- no matching key is never visited and survives into the response verbatim. A
    -- new templates/ deployed against an older lib/ - a commit-pin rollback that
    -- leaves the templates alone - then serves a page with the literal text
    -- {{captcha_frontend_js_tag}} in it, no script tag, no widget, and nothing in
    -- the log to say so.
    --
    -- Reported rather than refused: '{{ }}' is also the delimiter of several
    -- client-side template languages, so a custom captcha page may legitimately
    -- contain a pair we know nothing about, and failing init over one would break a
    -- working deployment to catch a broken one. A named line in the error log is
    -- what was actually missing.
    local unresolved = view:match("{{[%w_]+}}")
    if unresolved ~= nil then
        ngx.log(ngx.ERR, "captcha template leaves " .. unresolved .. " unsubstituted in " ..
            TemplateFilePath .. " and it is served to visitors as literal text. If this " ..
            "is a placeholder this bouncer should populate, lib/ and templates/ are from " ..
            "different versions; if it belongs to a client-side template, ignore this line")
    end

    M.Template = view

    if M.CaptchaProvider == "altcha" then
        -- Split once here so serving a challenge is a couple of buffer writes,
        -- rather than a substitution across the whole page - the stock template
        -- inlines its CSS and runs to about 20 kB.
        local head, tail, why = split_altcha_view(view)
        if head == nil then
            -- This error return leaves the provider unusable, and csmod.Allow()
            -- calls ServeWidget() ahead of every gate it has. Without clearing the
            -- pair the bundle keeps being served, on every vhost, for a provider the
            -- bouncer has already declared it cannot use - which is most of the way
            -- to undiagnosable from the outside.
            M.WidgetPath = ""
            M.WidgetBody = ""
            return "captcha template " .. why .. " " .. TemplateFilePath
        end
        M.TemplateHead = head
        M.TemplateTail = tail
    end

    return nil
end

--- Answers a request for the self-hosted widget bundle.
-- Returns false when this request is not for it; does not return at all when it
-- is, having served the bundle. Called from csmod.Allow() before any remediation,
-- which matters for two reasons beyond covering every vhost from one place:
--
--   * the script is fetched by a browser whose address is being captcha'd, and
--     every request from such an address is otherwise answered with the captcha
--     page. The browser would receive HTML where it expected a module, and the
--     element would never upgrade.
--   * serving the captcha page also rewrites the URI the visitor is released to
--     once they solve. A bounced subresource fetch would send them to the script
--     instead of the page they asked for - the same trap /favicon.ico is exempt
--     from in csmod.Allow().
function M.ServeWidget()
    if M.WidgetPath == "" or ngx.var.uri ~= M.WidgetPath then
        return false
    end

    ngx.header.content_type = "application/javascript; charset=utf-8"
    -- Cached hard, because the path is expected to carry the version (the shipped
    -- configuration names the file altcha-<version>.js): a new bundle then arrives
    -- under a new URL instead of as a revalidation of this one.
    ngx.header.cache_control = "public, max-age=31536000, immutable"
    -- Known since init and fixed for the process lifetime, so setting it costs
    -- nothing and saves the response being chunked on HTTP/1.1. Note the bundle
    -- goes out as application/javascript, which is not in nginx's default
    -- gzip_types - see the self-hosting section of the README.
    ngx.header.content_length = #M.WidgetBody
    ngx.status = ngx.HTTP_OK
    -- print, not say: say appends a newline, and this is a byte-exact copy of a
    -- file whose checksum the operator may well be checking
    ngx.print(M.WidgetBody)
    ngx.exit(ngx.HTTP_OK)
end

-- Whether the visitor's browser is plausibly in a secure context, as far as that can
-- be judged from here: TLS on this hop, an operator saying so for this vhost, or a
-- loopback origin, which browsers treat as secure whatever the scheme.
--
-- X-Forwarded-Proto is deliberately not consulted. There is no way from here to tell
-- "the trusted proxy set this" from "the client sent it and the proxy passed it
-- through": nginx does not record who wrote a header, and realip only proves a trusted
-- proxy is somewhere in the path, never that it vouched for this particular header.
-- Those two come apart whenever a proxy sets X-Forwarded-For but not
-- X-Forwarded-Proto, which is the common half-configured case, and t/27 used to assert
-- a client-supplied header being honoured - the bypass, written down as the feature. A
-- deployment terminating TLS upstream says so with $crowdsec_assume_secure instead,
-- which is an assertion the operator makes rather than a guess we make from something
-- the visitor can send.
--
-- Getting served the captcha page where the gate would have denied is not a harmless
-- downgrade: altcha's challenge is deliberately solvable without a browser - t/25 pays
-- one in about forty lines of Perl - so forging past this buys a scriptable release
-- from a denial, not merely the page the gate would have spared you. That is why every
-- branch below is either nginx's own knowledge or the operator's explicit word.
local function browser_context_is_secure()
    if ngx.var.scheme == "https" then
        return true
    end

    -- The operator's assertion for this vhost, in the shape the bouncer already uses
    -- for its other switches: `set $crowdsec_assume_secure 1;` in a server block.
    -- This is the only way to describe a proxy that terminates TLS and forwards over
    -- plain HTTP, however it announces itself (X-Forwarded-Proto, X-Forwarded-Protocol,
    -- X-Url-Scheme, Front-End-Https, or nothing at all). Without it every captcha
    -- decision on such a vhost becomes a denial telling an HTTPS visitor to retry over
    -- HTTPS, which the operator cannot tell from genuine plain HTTP in the log.
    if ngx.var.crowdsec_assume_secure == "1" then
        return true
    end

    -- The browser's own rule, not a heuristic: localhost, *.localhost and the loopback
    -- literals are secure contexts, which is what keeps local development over plain
    -- http on the captcha page rather than the denial below.
    --
    -- Paired with the TCP peer, because the Host alone is the client's to choose: a
    -- remote scanner sending "Host: localhost" would otherwise be handed a challenge it
    -- can solve without a browser.
    --
    -- KNOWN GAP, deliberately not closed here. The peer is the *proxy* whenever realip
    -- is active, so behind a proxy on loopback - a same-host nginx, HAProxy or Varnish,
    -- or a sidecar sharing the network namespace - it is 127.0.0.1 for every request
    -- whatever the client's address, and a remote client sending "Host: localhost" to a
    -- plaintext vhost still passes. The address the bouncer actually decides about is
    -- ngx.var.remote_addr (what csmod.Allow() is handed), and comparing that instead is
    -- the fix - but it flips every captcha suite, which reaches this branch via a
    -- loopback Host with a forwarded remote address, so each needs
    -- `set $crowdsec_assume_secure 1;` first. Tracked rather than half-done.
    --
    -- A container whose browser is on the host arrives from the bridge gateway rather
    -- than loopback, so that case wants $crowdsec_assume_secure too.
    local host = ngx.var.host
    if host == nil then
        return false
    end
    local host_is_loopback = host == "localhost" or utils.ends_with(host, ".localhost")
        or host == "127.0.0.1" or host == "::1" or host == "[::1]"
    if not host_is_loopback then
        return false
    end
    local peer = ngx.var.realip_remote_addr or ngx.var.remote_addr
    return peer ~= nil and (peer == "::1" or peer == "::ffff:127.0.0.1"
        or utils.starts_with(peer, "127."))
end

--- Whether a captcha can usefully be served for this request at all.
--
-- Exported so csmod.Allow() can ask before it commits state. M.apply() checks the same
-- predicate, and has to, because it is also the thing that renders the page - but by
-- the time it answers, the caller has already written a VERIFY_STATE entry into
-- crowdsec_cache for a captcha that is about to be refused. Those are attacker-paced
-- writes into the same shared dict that holds the decision cache, which is the exact
-- amplification altcha.New() refuses to allow for challenges.
--
-- One predicate, two callers: this returns the same answer M.apply() will act on.
function M.CanServe()
    return browser_context_is_secure()
end

-- ret_code is the status the appsec component asked for, or nil when the decision
-- came from the LAPI. It is only consulted on the ban fallback below, so that
-- serving a ban from here matches what csmod.Allow's own ban arms would have sent.
function M.apply(remote_ip, ret_code)
    -- This library is packaged by several bouncers, and apply() took no arguments
    -- before the altcha work - a caller still on that signature passes nil, and
    -- the log concatenations below would turn its captcha decision into a 500 out
    -- of the access phase. The request's address is the value it meant anyway.
    if remote_ip == nil then
        remote_ip = ngx.var.remote_addr
    end

    -- Anything that can decide not to serve a captcha page has to happen before the
    -- first header is set. Handing off to ban.apply() with captcha's status and
    -- headers already committed leaves the ban wearing them - harmless today, since
    -- nothing is flushed yet, but the wrong shape to leave for whoever adds the next
    -- header here.

    -- A captcha enforced over plain HTTP strands a human visitor: altcha's widget
    -- derives keys with crypto.subtle, which browsers expose only in secure
    -- contexts, so it errors before doing any work. The gate applies to every
    -- provider rather than special-casing altcha - a security check running over
    -- plaintext is not worth much, and one behaviour is easier to reason about than
    -- four. Checked before the challenge is minted so the visitor's mint budget is
    -- not charged for a page they would never have been able to use.
    if not browser_context_is_secure() then
        -- The upgrade hint, emitted once per worker and above nginx's default
        -- error_log level, because the two per-request lines below are not.
        --
        -- This deployment sent X-Forwarded-Proto: https and is being denied anyway,
        -- which is the shape of "TLS is terminated upstream and nobody has set
        -- $crowdsec_assume_secure yet". The per-request lines cannot say that: from
        -- here a genuinely plain-HTTP request and a misconfigured proxied one are
        -- identical, which is exactly the ambiguity the README calls out.
        --
        -- Reading the header for a diagnostic gives up nothing the gate refuses to
        -- give up. A client that forges it buys one log line per worker, not a
        -- challenge - the decision above has already been taken without it.
        if not forwarded_proto_hint_logged then
            local claimed = ngx.var.http_x_forwarded_proto
            if claimed ~= nil and claimed:lower():find("https", 1, true) ~= nil then
                forwarded_proto_hint_logged = true
                ngx.log(ngx.ERR, "captcha refused for '" .. tostring(ngx.var.host) ..
                    "': this request claims X-Forwarded-Proto: https, which this bouncer " ..
                    "does not trust because nginx cannot tell a proxy's header from one a " ..
                    "client sent. If TLS is terminated upstream, add " ..
                    "`set $crowdsec_assume_secure 1;` to that server block, or every " ..
                    "captcha decision here stays a denial. Logged once per worker")
            end
        end
        -- Per-vhost override via `set $crowdsec_captcha_insecure_template <path>;`,
        -- served raw like the global one: the insecure page carries no widget, so
        -- there is nothing to compile or validate in a host's own copy.
        local insecure_page = utils.template_override(ngx.var.crowdsec_captcha_insecure_template) or M.InsecureTemplate
        if insecure_page ~= "" then
            -- INFO, not ERR: on a site serving plain HTTP this is the routine
            -- outcome for every bounced request, and a bot hammering one endpoint
            -- must not be able to bury genuine errors. The no-page branch below
            -- stays at ERR because it reflects configuration worth changing.
            ngx.log(ngx.INFO, "captcha for '" .. remote_ip ..
                "' cannot run over plain HTTP, serving the insecure-context page instead")
            -- the same status a ban would carry (RET_CODE, or the appsec status when
            -- the decision came from there): this is a denial wearing a friendlier
            -- face, and a 200 would invite caches to keep it
            local status = ret_code
            if status == nil then
                status = ban.ret_code
            end
            ngx.header.content_type = "text/html"
            ngx.header.cache_control = "no-cache"
            ngx.status = status
            ngx.say(insecure_page)
            ngx.exit(status)
            return
        end
        ngx.log(ngx.ERR, "captcha for '" .. remote_ip ..
            "' cannot run over plain HTTP and no insecure-context page is configured, serving a ban instead")
        return ban.apply(ret_code)
    end

    local challenge
    if M.CaptchaProvider == "altcha" then
        -- one challenge per visitor, so it cannot be baked into the template at
        -- init the way the other providers' widgets are
        local err, reported
        challenge, err, reported = altcha.Challenge(remote_ip)
        if challenge == nil then
            -- Says which page actually went out: csmod.Allow() has already logged
            -- "denied with 'captcha'" by this point, and without this the ban that
            -- replaces it is invisible in the log.
            --
            -- Except when the failure is the mint budget shedding load, which happens
            -- once per flooded request. Challenge() reports it once per worker per
            -- second with a count; repeats inside that second set `reported` and are
            -- passed over here. Any other failure leaves it nil and is logged.
            if not reported then
                ngx.log(ngx.ERR, "failed to issue an altcha challenge, serving a ban instead: " .. tostring(err))
            end
            -- a page with no challenge is a dead end for the visitor, so drop them
            -- the way a ban would - through ban.apply rather than a bare 403, so
            -- RET_CODE, REDIRECT_LOCATION and BAN_TEMPLATE_PATH are honoured
            return ban.apply(ret_code)
        end
    end

    -- Per-vhost override via `set $crowdsec_captcha_template <path>;`, compiled
    -- per serve. Unlike the ban page this is not just a read - the widget markup
    -- has to be substituted in, and for altcha the page must carry exactly one
    -- challenge slot - so a host's broken page degrades to the stock one, loudly,
    -- rather than to a widget that cannot work. The compile is a few string
    -- passes; hosts without an override stay on the head/tail buffers prepared at
    -- init and pay only the variable read.
    local head, tail, body = M.TemplateHead, M.TemplateTail, M.Template
    local override = utils.template_override(ngx.var.crowdsec_captcha_template)
    if override ~= nil then
        local view = template.compile(override, M.TemplateData)
        if M.CaptchaProvider == "altcha" then
            local override_head, override_tail, why = split_altcha_view(view)
            if override_head == nil then
                ngx.log(ngx.ERR, "per-vhost captcha template for '" .. tostring(ngx.var.host) ..
                    "' " .. why .. " it, serving the stock captcha page instead")
            else
                head, tail = override_head, override_tail
            end
        else
            body = view
        end
    end

    ngx.header.content_type = "text/html"
    ngx.header.cache_control = "no-cache"
    ngx.status = M.ret_code

    if challenge ~= nil then
        ngx.say({head, challenge, tail})
    else
        ngx.say(body)
    end

    ngx.exit(M.ret_code)
end

function M.GetCaptchaBackendKey()
    return captcha_frontend_key[M.CaptchaProvider] .. "-response"
end

function table_to_encoded_url(args)
    local params = {}
    for k, v in pairs(args) do table.insert(params, k .. '=' .. v) end
    return table.concat(params, "&")
end

function M.Validate(captcha_res, remote_ip)
    -- ngx.req.get_post_args() does not always hand back a string: a field submitted
    -- with no '=' arrives as the boolean true, and one submitted twice arrives as a
    -- table. Both are non-nil, so both get this far. Everything below assumes a
    -- string - ngx.decode_base64() raises on anything else, and the form encoding
    -- the other providers use concatenates it - so without this a crafted POST is a
    -- 500 with a traceback rather than a failed captcha. Rejecting it here rather
    -- than in each provider covers all four.
    if type(captcha_res) ~= "string" then
      return false, nil
    end

    if M.CaptchaProvider == "altcha" then
      -- checked in-process against the challenge issued to this IP, so the IP is
      -- the lookup rather than something to forward to a service
      return altcha.Validate(captcha_res, remote_ip)
    end

    local body = {
        secret   = M.SecretKey,
        response = captcha_res,
        remoteip = remote_ip
    }

    local data = table_to_encoded_url(body)
    local httpc = http.new()
    httpc:set_timeout(2000)
    local res, err = httpc:request_uri(captcha_backend_url[M.CaptchaProvider], {
      method = "POST",
      body = data,
      headers = {
          ["Content-Type"] = "application/x-www-form-urlencoded",
      },
    })
    httpc:close()
    if err ~= nil then
      return true, err
    end

    local result = cjson.decode(res.body)

    if result.success == false then
      for k, v in pairs(result["error-codes"]) do
        if v == "invalid-input-secret" then
          ngx.log(ngx.ERR, "reCaptcha secret key is invalid")
          return true, nil
        end
      end 
    end

    return result.success, nil
end


return M

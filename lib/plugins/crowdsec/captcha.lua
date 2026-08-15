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

M.SecretKey = ""
M.SiteKey = ""
M.Template = ""
M.ret_code = ngx.HTTP_OK

function M.New(siteKey, secretKey, TemplateFilePath, captcha_provider, ret_code, altcha_cost, altcha_algorithm, altcha_complexity)

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

      local err = altcha.New(altcha_cost, altcha_algorithm, altcha_complexity)
      if err ~= nil then
        return err
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

    local template_data = {}
    -- still exported so templates written against the previous layout keep rendering
    template_data["captcha_site_key"] =  M.SiteKey
    template_data["captcha_frontend_js"] = captcha_frontend_js[M.CaptchaProvider]
    template_data["captcha_frontend_key"] = captcha_frontend_key[M.CaptchaProvider]

    -- providers disagree on how the widget is loaded and declared, and the template
    -- engine has no conditionals, so the markup is rendered here and injected whole
    if M.CaptchaProvider == "altcha" then
        template_data["captcha_frontend_js_tag"] =
            '<script async defer type="module" src="' .. captcha_frontend_js["altcha"] ..
            '" integrity="' .. captcha_frontend_js_integrity["altcha"] ..
            '" crossorigin="anonymous"></script>'
        -- No auto attribute, so the widget waits to be clicked rather than solving
        -- as the page paints - the same deliberate act the other providers ask for.
        -- The challenge itself is per-visitor, so a placeholder stands in here and
        -- M.apply() splices the visitor's own in.
        template_data["captcha_widget"] =
            '<altcha-widget id="captcha" name="' .. M.GetCaptchaBackendKey() ..
            '" challenge=\'' .. ALTCHA_CHALLENGE_PLACEHOLDER .. '\'></altcha-widget>' ..
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

    local view = template.compile(captcha_template, template_data)
    M.Template = view

    if M.CaptchaProvider == "altcha" then
        -- Split once here so serving a challenge is a couple of buffer writes,
        -- rather than a substitution across the whole page - the stock template
        -- inlines its CSS and runs to about 20 kB.
        local at = view:find(ALTCHA_CHALLENGE_PLACEHOLDER, 1, true)
        if at == nil then
            return "captcha template renders no altcha widget, add {{captcha_widget}} to " .. TemplateFilePath
        end
        -- Splitting at the first hit leaves any later one verbatim in the tail, so a
        -- second widget reaches the browser with the placeholder still in its
        -- challenge attribute. That does not start with '{', so the widget reads it
        -- as a URL to fetch a challenge from and errors on a path that does not
        -- exist - and the duplicate id makes the verified listener bind to whichever
        -- element parses first. Nothing about that is diagnosable from the page, so
        -- refuse here instead.
        if view:find(ALTCHA_CHALLENGE_PLACEHOLDER, at + #ALTCHA_CHALLENGE_PLACEHOLDER, true) ~= nil then
            return "captcha template renders more than one altcha widget, leave a single {{captcha_widget}} in " .. TemplateFilePath
        end
        M.TemplateHead = view:sub(1, at - 1)
        M.TemplateTail = view:sub(at + #ALTCHA_CHALLENGE_PLACEHOLDER)
    end

    return nil
end

-- ret_code is the status the appsec component asked for, or nil when the decision
-- came from the LAPI. It is only consulted on the ban fallback below, so that
-- serving a ban from here matches what csmod.Allow's own ban arms would have sent.
function M.apply(remote_ip, ret_code)
    -- Anything that can decide not to serve a captcha page has to happen before the
    -- first header is set. Handing off to ban.apply() with captcha's status and
    -- headers already committed leaves the ban wearing them - harmless today, since
    -- nothing is flushed yet, but the wrong shape to leave for whoever adds the next
    -- header here.
    local challenge
    if M.CaptchaProvider == "altcha" then
        -- one challenge per visitor, so it cannot be baked into the template at
        -- init the way the other providers' widgets are
        local err
        challenge, err = altcha.Challenge(remote_ip)
        if challenge == nil then
            -- Says which page actually went out: csmod.Allow() has already logged
            -- "denied with 'captcha'" by this point, and without this the ban that
            -- replaces it is invisible in the log.
            ngx.log(ngx.ERR, "failed to issue an altcha challenge, serving a ban instead: " .. tostring(err))
            -- a page with no challenge is a dead end for the visitor, so drop them
            -- the way a ban would - through ban.apply rather than a bare 403, so
            -- RET_CODE, REDIRECT_LOCATION and BAN_TEMPLATE_PATH are honoured
            return ban.apply(ret_code)
        end
    end

    ngx.header.content_type = "text/html"
    ngx.header.cache_control = "no-cache"
    ngx.status = M.ret_code

    if challenge ~= nil then
        ngx.say({M.TemplateHead, challenge, M.TemplateTail})
    else
        ngx.say(M.Template)
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

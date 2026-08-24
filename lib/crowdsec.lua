package.path = package.path .. ";./?.lua"

local config = require "plugins.crowdsec.config"
local iputils = require "plugins.crowdsec.iputils"
local http = require "resty.http"
local cjson = require "cjson"
local captcha = require "plugins.crowdsec.captcha"
local flag = require "plugins.crowdsec.flag"
local utils = require "plugins.crowdsec.utils"
local ban = require "plugins.crowdsec.ban"
local challenge = require "plugins.crowdsec.challenge"
local url = require "plugins.crowdsec.url"
local metrics = require "plugins.crowdsec.metrics"
local live = require "plugins.crowdsec.live"
local stream = require "plugins.crowdsec.stream"
local bit

if _VERSION == "Lua 5.1" then bit = require "bit" else bit = require "bit32" end

local runtime = {}

runtime.timer_started = false -- worker wide variable

local csmod = {}

local DENY = "deny"

-- How long a served captcha page stays redeemable: the window between handing a
-- visitor the page and accepting their solution. Was a bare 60 mid-function, which
-- self-solving widgets rarely noticed but slow hardware did - the altcha work now
-- starts as the page paints, and this is the whole budget it has to finish inside,
-- so it is sized for a modest phone rather than a fast laptop. Kept well under
-- altcha's 1200s challenge TTL so a re-served page still carries a live challenge.
local CAPTCHA_VERIFY_TTL = 300

local APPSEC_API_KEY_HEADER = "x-crowdsec-appsec-api-key"
local APPSEC_IP_HEADER = "x-crowdsec-appsec-ip"
local APPSEC_HOST_HEADER = "x-crowdsec-appsec-host"
local APPSEC_VERB_HEADER = "x-crowdsec-appsec-verb"
local APPSEC_URI_HEADER = "x-crowdsec-appsec-uri"
local APPSEC_USER_AGENT_HEADER = "x-crowdsec-appsec-user-agent"
local APPSEC_TRANSFER_ENCODING_HEADER = "x-crowdsec-appsec-transfer-encoding"
local REMEDIATION_API_KEY_HEADER = 'x-api-key'
local METRICS_PERIOD = 900

local METHODS_WITH_BODY = {
  POST = true,
  PUT = true,
  PATCH = true,
  DELETE = true,
}

--- only for debug purpose
--- called only from within the nginx configuration file in the CI
function csmod.debug_metrics()
    METRICS_PERIOD = 15
    ngx.log(ngx.DEBUG, "Shortening metrics period to 15 seconds")
end

function csmod.get_mode()
  return runtime.conf["MODE"]
end

--- return the configuration
local function is_bouncer_enabled()
  if ngx.var.crowdsec_disable_bouncer == "1" then
    return false
  end
  if ngx.var.crowdsec_enable_bouncer == "1" then
    return true
  end
  if runtime.conf["ENABLED"] == "true"  then --- this one is a string
    return true
  end

  return false
end

local function is_appsec_enabled()
  if ngx.var.crowdsec_disable_appsec == "1" then
    return false
  end
  if ngx.var.crowdsec_enable_appsec == "1" then
    return true
  end
  if runtime.conf["APPSEC_ENABLED"] then --- this one is truly a boolean
    return true
  end

  return false
end

local function is_always_send_to_appsec()
  if ngx.var.crowdsec_always_send_to_appsec == "1" then
    return true
  end
  if runtime.conf["ALWAYS_SEND_TO_APPSEC"] then --- this one is truly a boolean
    return true
  end

  return false
end

--- init function
-- init function called by nginx in init_by_lua_block
-- @param configFile path to the configuration file
-- @param userAgent the user agent of the bouncer
-- @return boolean: true if the init is successful, false otherwise
function csmod.init(configFile, userAgent)
  local conf, err = config.loadConfig(configFile, true)
  if conf == nil then
    return nil, err
  end
  local localConf, _ = config.loadConfig(configFile .. ".local", false)
  if localConf ~= nil then
    for k, v in pairs(localConf) do
      conf[k] = v
    end
  end
  runtime.conf = conf
  runtime.userAgent = userAgent
  runtime.cache = ngx.shared.crowdsec_cache
  runtime.fallback = runtime.conf["FALLBACK_REMEDIATION"]

  if runtime.conf["ENABLED"] == "false" then
    return "Disabled", nil
  end

  if runtime.conf["REDIRECT_LOCATION"] == "/" then
    ngx.log(ngx.ERR, "redirect location is set to '/' this will lead into infinite redirection")
  end

  -- Whether the captcha plugin configured successfully. Module state rather than a
  -- crowdsec_cache entry: it is derived once from configuration, identical in every
  -- worker (init_by_lua runs before workers fork) and never mutated after init, so
  -- sharing bought nothing - and a dict entry can be evicted, which converted every
  -- captcha decision into FALLBACK_REMEDIATION for the dict's remaining lifetime
  -- the moment memory pressure pushed the flag out.
  --
  -- An empty CAPTCHA_PROVIDER= line is how a configuration says "no captcha here" -
  -- the stock CrowdSec config ships exactly that shape - so it is stated once at
  -- startup rather than reported as the error an unsupported value is.
  runtime.captcha_ok = true
  if (runtime.conf["CAPTCHA_PROVIDER"] or "") == "" then
    runtime.captcha_ok = false
    ngx.log(ngx.NOTICE, "CAPTCHA_PROVIDER is not set, captcha decisions will be served the fallback remediation")
  else
    local err = captcha.New(runtime.conf["SITE_KEY"], runtime.conf["SECRET_KEY"], runtime.conf["CAPTCHA_TEMPLATE_PATH"], runtime.conf["CAPTCHA_PROVIDER"], runtime.conf["CAPTCHA_RET_CODE"], runtime.conf["ALTCHA_COST"], runtime.conf["ALTCHA_ALGORITHM"], runtime.conf["ALTCHA_COMPLEXITY"], runtime.conf["CAPTCHA_INSECURE_TEMPLATE_PATH"], runtime.conf["ALTCHA_WIDGET_FILE"], runtime.conf["ALTCHA_WIDGET_PATH"])
    if err ~= nil then
      ngx.log(ngx.ERR, "error loading captcha plugin: " .. err)
      runtime.captcha_ok = false
    end
  end


  -- FALLBACK_REMEDIATION=captcha is a valid, documented value, and with no captcha
  -- to serve it makes the fallback chain in Allow() rewrite captcha to captcha: the
  -- ban arm does not match, the challenge arm does not match, the captcha arm is
  -- gated on captcha_ok, and the request falls through to DECLINED - allowed, with
  -- no log line, for as long as the provider stays broken. OVERRIDE_REMEDIATION
  -- widens that from captcha decisions to every decision the LAPI returns.
  --
  -- Settled here rather than per request, because everything needed to settle it is
  -- already known: the documented promise is that an unusable captcha "degrades to
  -- FALLBACK_REMEDIATION", and degrading to something unservable is not degrading.
  if runtime.fallback == "captcha" and not runtime.captcha_ok then
    ngx.log(ngx.ERR, "FALLBACK_REMEDIATION is 'captcha' but no captcha can be served, " ..
      "falling back to 'ban' instead - a captcha fallback for a broken captcha provider " ..
      "would allow every bounced request through")
    runtime.fallback = "ban"
    -- Both, so the two cannot disagree. csmod.AppSecCheck() is public and reads the
    -- config value rather than runtime.fallback; it happens to come out right today
    -- because its remediation flows back through the chain in Allow(), but "settled
    -- at init" has to mean settled for every reader, not just the one downstream.
    runtime.conf["FALLBACK_REMEDIATION"] = "ban"
  end

  local err = ban.new(runtime.conf["BAN_TEMPLATE_PATH"], runtime.conf["REDIRECT_LOCATION"], runtime.conf["RET_CODE"])
  if err ~= nil then
    ngx.log(ngx.ERR, "error loading ban plugins: " .. err)
  end

  if runtime.conf["REDIRECT_LOCATION"] ~= "" then
    table.insert(runtime.conf["EXCLUDE_LOCATION"], runtime.conf["REDIRECT_LOCATION"])
  end

  if runtime.conf["SSL_VERIFY"] == "false" then
    runtime.conf["SSL_VERIFY"] = false
  else
    runtime.conf["SSL_VERIFY"] = true
  end

  if runtime.conf["USE_TLS_AUTH"] == "true" then
    runtime.conf["USE_TLS_AUTH"] = true
  else
    runtime.conf["USE_TLS_AUTH"] = false
  end

  -- Parse TLS certificates and keys if mTLS authentication is enabled
  if runtime.conf["USE_TLS_AUTH"] then
    local ssl = require "ngx.ssl"

    -- Parse client certificate
    if runtime.conf["TLS_CLIENT_CERT"] ~= "" then
      local cert_file, err = io.open(runtime.conf["TLS_CLIENT_CERT"], "r")
      if not cert_file then
        ngx.log(ngx.ERR, "Failed to open client certificate file: " .. (err or "unknown error"))
        return nil, "Failed to open client certificate file: " .. (err or "unknown error")
      end
      local cert_data = cert_file:read("*all")
      cert_file:close()
      local cert, err = ssl.parse_pem_cert(cert_data)
      if not cert then
        ngx.log(ngx.ERR, "Failed to parse client certificate: " .. (err or "unknown error"))
        return nil, "Failed to parse client certificate: " .. (err or "unknown error")
      end
      runtime.conf["TLS_CLIENT_CERT_PARSED"] = cert
      ngx.log(ngx.INFO, "Successfully parsed TLS client certificate")
    else
      ngx.log(ngx.ERR, "TLS_CLIENT_CERT path is required when USE_TLS_AUTH is enabled")
      return nil, "TLS_CLIENT_CERT path is required when USE_TLS_AUTH is enabled"
    end

    -- Parse client private key
    if runtime.conf["TLS_CLIENT_KEY"] ~= "" then
      local key_file, err = io.open(runtime.conf["TLS_CLIENT_KEY"], "r")
      if not key_file then
        ngx.log(ngx.ERR, "Failed to open client private key: " .. (err or "unknown error"))
        return nil, "Failed to open client private key: " .. (err or "unknown error")
      end
      local key_data = key_file:read("*all")
      key_file:close()
      local key, err = ssl.parse_pem_priv_key(key_data)
      if not key then
        ngx.log(ngx.ERR, "Failed to parse client private key: " .. (err or "unknown error"))
        return nil, "Failed to parse client private key: " .. (err or "unknown error")
      end
      runtime.conf["TLS_CLIENT_KEY_PARSED"] = key
      ngx.log(ngx.INFO, "Successfully parsed TLS client private key")
    else
      ngx.log(ngx.ERR, "TLS_CLIENT_KEY path is required when USE_TLS_AUTH is enabled")
      return nil, "TLS_CLIENT_KEY path is required when USE_TLS_AUTH is enabled"
    end
  end

  local succ, err, forcible = runtime.cache:set("metrics_startup_time", ngx.time())  -- to make sure we have only one thread sending metrics
  if not succ then
    ngx.log(ngx.ERR, "failed to add metrics_startup_time key in cache: "..err)
  end
  if forcible then
    ngx.log(ngx.ERR, "Lua shared dict (crowdsec cache) is full, please increase dict size in config")
  end
  local succ, err, forcible = runtime.cache:set("metrics_first_run",true) -- to avoid sending metrics before the first period
  if not succ then
    ngx.log(ngx.ERR, "failed to add metrics_first_run key in cache: "..err)
  end
  if forcible then
    ngx.log(ngx.ERR, "Lua shared dict (crowdsec cache) is full, please increase dict size in config")
  end

  if runtime.conf["ALWAYS_SEND_TO_APPSEC"] == "false" then
    runtime.conf["ALWAYS_SEND_TO_APPSEC"] = false
  else
    runtime.conf["ALWAYS_SEND_TO_APPSEC"] = true
  end

  if runtime.conf["APPSEC_DROP_UNREADABLE_BODY"] == "true" then
    runtime.conf["APPSEC_DROP_UNREADABLE_BODY"] = true
  else
    runtime.conf["APPSEC_DROP_UNREADABLE_BODY"] = false
  end

  runtime.conf["APPSEC_ENABLED"] = false

  if runtime.conf["APPSEC_URL"] ~= "" then
    local u = url.parse(runtime.conf["APPSEC_URL"])
    runtime.conf["APPSEC_ENABLED"] = true
    runtime.conf["APPSEC_HOST"] = u.host
    if u.port ~= nil then
      runtime.conf["APPSEC_HOST"] = runtime.conf["APPSEC_HOST"] .. ":" .. u.port
    end
    ngx.log(ngx.ERR, "APPSEC is enabled on '" .. runtime.conf["APPSEC_HOST"] .. "'")
  end


  if runtime.conf["MODE"] == "stream" then
    local succ, err, forcible = runtime.cache:set("startup", true)
    if not succ then
      ngx.log(ngx.ERR, "failed to add startup key in cache: "..err)
    end
    if forcible then
      ngx.log(ngx.ERR, "Lua shared dict (crowdsec cache) is full, please increase dict size in config")
    end
    local succ, err, forcible = runtime.cache:set("first_run", true)
    if not succ then
      ngx.log(ngx.ERR, "failed to add first_run key in cache: "..err)
    end
    if forcible then
      ngx.log(ngx.ERR, "Lua shared dict (crowdsec cache) is full, please increase dict size in config")
    end
  end

  if runtime.conf["API_URL"] == "" and  runtime.conf["APPSEC_URL"] == "" then
    ngx.log(ngx.ERR, "Neither API_URL or APPSEC_URL are defined, remediation component will not do anything")
  end

  if runtime.conf["API_URL"] == "" and  runtime.conf["APPSEC_URL"] ~= "" then
    ngx.log(ngx.ERR, "Only APPSEC_URL is defined, local API decisions will be ignored")
  end



  local tmp =  runtime.conf["API_URL"]:gsub("/+$","")
  if tmp ~= runtime.conf["API_URL"] then
    ngx.log(ngx.DEBUG, "trailing slash in API_URL removed: " .. tmp)
    runtime.conf["API_URL"] = tmp
  end

  if runtime.conf["MODE"] == "live" then
    ngx.log(ngx.INFO, "lua nginx bouncer enabled with live mode")
    live:new()
  else
    ngx.log(ngx.INFO, "lua nginx bouncer enabled with stream mode")
    stream:new()
  end
  return true, nil
end


--- The idea here is to setup the timer that will trigger the metrics sending
--- If first run then just fire the new timer to run the function again in METRICS_PERIOD
--- If not send metrics and run the timer again in METRICS_PERIOD
function csmod.SetupMetrics()
  -- if no API_URL, we don't setup metrics
  if runtime.conf["API_URL"] == "" then
    return
  end

  local function Setup_metrics_timer()
    if ngx.worker.exiting() then
      ngx.log(ngx.INFO, "worker is exiting, not setting up metrics timer")
      return
    end
    local ok, err = ngx.timer.at(METRICS_PERIOD, csmod.SetupMetrics)
    if not ok then
      error("Failed to create the timer: " .. (err or "unknown"))
    else
      ngx.log(ngx.DEBUG, "Metrics timer started in " .. tostring(METRICS_PERIOD) .. " seconds")
    end
  end
  local first_run = runtime.cache:get("metrics_first_run")
  if first_run then
    ngx.log(ngx.DEBUG, "First run for setup metrics ")
    metrics:new(runtime.userAgent)
    runtime.cache:set("metrics_first_run",false)
    Setup_metrics_timer()
    return
  end
  local started = runtime.cache:get("metrics_startup_time")
  if ngx.time() - started >= METRICS_PERIOD then
    if runtime.conf["MODE"] == "stream" then
      stream:refresh_metrics()
    end
    metrics:sendMetrics(
      runtime.conf["API_URL"],
      {['User-Agent']=runtime.userAgent,[REMEDIATION_API_KEY_HEADER]=runtime.conf["API_KEY"],["Content-Type"]="application/json"},
      runtime.conf["SSL_VERIFY"],
      METRICS_PERIOD
    )
    local succ, err, forcible = runtime.cache:set("metrics_startup_time", ngx.time())  -- to make sure we have only one thread sending metrics
    if not succ then
      ngx.log(ngx.ERR, "failed to add metrics_startup_time key in cache: "..err)
    end
    if forcible then
      ngx.log(ngx.ERR, "Lua shared dict (crowdsec cache) is full, please increase dict size in config")
    end
    --
    --TODO rename the cache key
    Setup_metrics_timer()
  end
end




function csmod.validateCaptcha(captcha_res, remote_ip)
  return captcha.Validate(captcha_res, remote_ip)
end


local function get_body()

  -- the LUA module requires a content-length header to read a body for HTTP 2/3 requests, although it's not mandatory.
  -- This means that we will likely miss body, but AFAIK, there's no workaround for this.
  -- do not even try to read the body if there's no content-length as the LUA API will throw an error
  if ngx.req.http_version() >= 2 and ngx.var.http_content_length == nil then
    ngx.log(ngx.DEBUG, "No content-length header in request")
    return nil, METHODS_WITH_BODY[ngx.var.request_method] == true
  end
  ngx.req.read_body()
  local body = ngx.req.get_body_data()
  if body == nil then
    local bodyfile = ngx.req.get_body_file()
    if bodyfile then
      local fh, err = io.open(bodyfile, "r")
      if fh then
        body = fh:read("*a")
        fh:close()
      end
    end
  end
  return body, false
end

function csmod.GetCaptchaBackendKey()
  return captcha.GetCaptchaBackendKey()
end

function csmod.SetupStream()
  local function SetupStreamTimer()
    if ngx.worker.exiting() then
      ngx.log(ngx.INFO, "worker is exiting, not setting up stream timer")
      return
    end
    local last_refresh = stream.cache:get("last_refresh")
    if last_refresh ~= nil then
      if ngx.time() - last_refresh < runtime.conf["UPDATE_FREQUENCY"] then
        ngx.log(ngx.DEBUG, "last refresh was less than " .. runtime.conf["UPDATE_FREQUENCY"] .. " seconds ago, returning")
        local ok, err = ngx.timer.at(runtime.conf["UPDATE_FREQUENCY"], SetupStreamTimer)
        if not ok then
          error("Failed to create the timer: " .. (err or "unknown"))
        end
        return
      end
    end
    local refreshing = stream.cache:get("refreshing")
    if not refreshing then
      local err
      if runtime.conf["USE_TLS_AUTH"] then
        err = stream:stream_query_tls(
          runtime.conf["API_URL"],
          runtime.conf["REQUEST_TIMEOUT"],
          runtime.userAgent,
          runtime.conf["SSL_VERIFY"],
          runtime.conf["TLS_CLIENT_CERT_PARSED"],
          runtime.conf["TLS_CLIENT_KEY_PARSED"],
          runtime.conf["BOUNCING_ON_TYPE"],
          runtime.conf["SCENARIOS_CONTAINING"],
          runtime.conf["SCENARIOS_NOT_CONTAINING"]
        )
      else
        err = stream:stream_query_api(
          runtime.conf["API_URL"],
          runtime.conf["REQUEST_TIMEOUT"],
          REMEDIATION_API_KEY_HEADER,
          runtime.conf["API_KEY"],
          runtime.userAgent,
          runtime.conf["SSL_VERIFY"],
          runtime.conf["BOUNCING_ON_TYPE"],
          runtime.conf["SCENARIOS_CONTAINING"],
          runtime.conf["SCENARIOS_NOT_CONTAINING"]
        )
      end
      if err ~=nil then
        ngx.log(ngx.ERR, "Failed to query the stream: " .. err)
      end
    end
    local ok, err = ngx.timer.at(runtime.conf["UPDATE_FREQUENCY"], SetupStreamTimer)
    if not ok then
      error("Failed to create the timer: " .. (err or "unknown"))
    end
  end
  -- if it stream mode and startup start timer
  if runtime.conf["API_URL"] == "" then
    return
  end

  ngx.log(ngx.DEBUG, "running timers: " .. tostring(ngx.timer.running_count()) .. " | pending timers: " .. tostring(ngx.timer.pending_count()))
  local refreshing = stream.cache:get("refreshing")

  if refreshing == true and not ngx.worker.exiting() then
    ngx.log(ngx.DEBUG, "another worker is refreshing the data, returning")
    local ok, err = ngx.timer.at(runtime.conf["UPDATE_FREQUENCY"], SetupStreamTimer)
    if not ok then
      error("Failed to create the timer: " .. (err or "unknown"))
    end
    return
  end


  -- This is done once per worker
  ngx.log(ngx.DEBUG, "timer started: " .. tostring(runtime.timer_started) .. " in worker " .. tostring(ngx.worker.id()))
  if not runtime.timer_started and not ngx.worker.exiting() then
    local ok, err
    ok, err = ngx.timer.at(runtime.conf["UPDATE_FREQUENCY"],SetupStreamTimer)
    if not ok then
      return true, nil, "Failed to create the timer: " .. (err or "unknown")
    end
    runtime.timer_started = true
    ngx.log(ngx.DEBUG, "Timer launched")
  end
end

---
--- Allow the IP
--- @param ip the IP to check
--- @return boolean: true if the IP is allowed, false otherwise
--- @return string: the remediation to apply
--- @return string: the error message if any
function csmod.allowIp(ip)
  if runtime.conf == nil then
    return true, nil, "Configuration is bad, cannot run properly"
  end

  if runtime.conf["API_URL"] == "" then
    return true, nil, nil
  end

  local key, ip_version = utils.item_to_string(ip, "ip")
  if key == nil then
    return true, nil, "Check failed '" .. ip .. "' has no valid IP address"
  end
  local key_parts = {}
  for i in key.gmatch(key, "([^_]+)") do
    table.insert(key_parts, i)
  end

  metrics:increment("processed", 1,  {ip_type=ip_version})

  local key_type = key_parts[1]
  if key_type == "normal" then
    local decision_string, flag_id = runtime.cache:get("decision_cache/" .. key)
    ngx.log(ngx.DEBUG, "[CACHE] Looking for '" .. key .. "' in cache")
    local  t = utils.split_on_delimiter(decision_string,"/")
    if t == nil then
      return true, nil, "Failed to split decision string"
    end
    ngx.log(ngx.DEBUG, "'" .. key .. "' is in cache")

    local remediation = ""
    if t[2] ~= nil then
      metrics:increment("dropped" ,1, {ip_type=ip_version, origin=t[2]})
    end
    if t[1] ~= nil then
      remediation = t[1]
    end
    return flag_id == 1, remediation, nil
  end

  local ip_network_address = key_parts[3]
  local netmasks = iputils.netmasks_by_key_type[key_type]
  for i, netmask in pairs(netmasks) do
    local item
    if key_type == "ipv4" then
      item = key_type.."_"..netmask.."_"..iputils.ipv4_band(ip_network_address, netmask)
    end
    if key_type == "ipv6" then
      item = key_type.."_"..table.concat(netmask, ":").."_"..iputils.ipv6_band(ip_network_address, netmask)
    end
    local decision_string, flag_id = runtime.cache:get("decision_cache/" .. item)
    ngx.log(ngx.DEBUG, "[CACHE] Looking for '" .. key .. "' in cache")
    if decision_string ~= nil then -- we have it in cache
      if decision_string == "none" then
        ngx.log(ngx.DEBUG, "[CACHE]'" .. key .. "' is in cache with value'" .. decision_string .. "'")
        return true, nil, nil
      end
      ngx.log(ngx.DEBUG, "'" .. key .. "' is in cache with value'" .. decision_string .. "'")
      local  t = utils.split_on_delimiter(decision_string,"/")
      if t == nil then
        return true, nil, "Failed to split decision string"
      end
      local remediation = ""
      if t[2] ~= nil then
        ngx.log(ngx.DEBUG, "'" .. "ipversion: " .. ip_version .. " origin: " .. t[2] .. "' is counted")
        metrics:increment("dropped", 1, {ip_type=ip_version, origin=t[2]}) -- origin: at this point we are pretty sure there's one
        -- and that the decision is a blocking
      end
      if t[1] ~= nil then
        remediation = t[1] -- remediation
      end
      -- flag_id is 1 if the decision is a not blocking one
      return flag_id == 1, remediation, nil
    end
  end

  -- if live mode, query lapi
  if runtime.conf["MODE"] == "live" then
    ngx.log(ngx.DEBUG, "live mode")
    local ok, remediation, origin, err
    if runtime.conf["USE_TLS_AUTH"] then
      ok, remediation, origin, err = live:live_query_tls(
        ip,
        runtime.conf["API_URL"],
        runtime.conf["REQUEST_TIMEOUT"],
        runtime.conf["CACHE_EXPIRATION"],
        runtime.userAgent,
        runtime.conf["SSL_VERIFY"],
        runtime.conf["TLS_CLIENT_CERT_PARSED"],
        runtime.conf["TLS_CLIENT_KEY_PARSED"],
        runtime.conf["BOUNCING_ON_TYPE"],
        runtime.conf["SCENARIOS_CONTAINING"],
        runtime.conf["SCENARIOS_NOT_CONTAINING"]
      )
    else
      ok, remediation, origin, err = live:live_query_api(
        ip,
        runtime.conf["API_URL"],
        runtime.conf["REQUEST_TIMEOUT"],
        runtime.conf["CACHE_EXPIRATION"],
        REMEDIATION_API_KEY_HEADER,
        runtime.conf['API_KEY'],
        runtime.userAgent,
        runtime.conf["SSL_VERIFY"],
        runtime.conf["BOUNCING_ON_TYPE"],
        runtime.conf["SCENARIOS_CONTAINING"],
        runtime.conf["SCENARIOS_NOT_CONTAINING"]
      )
    end
    -- debug: wip
    ngx.log(ngx.DEBUG, "live_query: " .. ip .. " | " .. (ok and "not banned with" or "banned with") .. " | " .. tostring(remediation) .. " | " .. tostring(origin) .. " | " .. tostring(err))
    local _, is_ipv4 = iputils.parseIPAddress(ip)
    if is_ipv4 then
      ip_version = "ipv4"
    else
      ip_version = "ipv6"
    end

    if remediation ~= nil and remediation == "ban" then
      metrics:increment("dropped", 1, {ip_type=ip_version, origin=origin} )
    end
    return ok, remediation, err
  end
  return true, nil, nil
end

--- @return boolean: true if the IP did not trigger any WAF rule, false otherwise
--- @return string: remediation returned by the WAF
--- @return number: HTTP status code to return to the client
--- @return table: if the WAF returned a challenge, this table contains the body, headers and cookies to return to the client
--- @return string|nil: error message if any, nil otherwise
function csmod.AppSecCheck(ip)
  local httpc = http.new()
  httpc:set_timeouts(runtime.conf["APPSEC_CONNECT_TIMEOUT"], runtime.conf["APPSEC_SEND_TIMEOUT"], runtime.conf["APPSEC_PROCESS_TIMEOUT"])

  local uri = ngx.var.request_uri
  local headers = ngx.req.get_headers()

  -- overwrite headers with crowdsec appsec require headers
  headers[APPSEC_IP_HEADER] = ip
  headers[APPSEC_HOST_HEADER] = ngx.var.http_host
  headers[APPSEC_VERB_HEADER] = ngx.var.request_method
  headers[APPSEC_URI_HEADER] = uri
  headers[APPSEC_USER_AGENT_HEADER] = ngx.var.http_user_agent
  headers[APPSEC_API_KEY_HEADER] = runtime.conf["API_KEY"]

  -- set CrowdSec APPSEC Host
  headers["host"] = runtime.conf["APPSEC_HOST"]

  local ok, remediation, status_code = true, "allow", 200
  if runtime.conf["APPSEC_FAILURE_ACTION"] == DENY then
    ok = false
    remediation = runtime.conf["FALLBACK_REMEDIATION"]
  end

  local method = "GET"

  local body, unreadable_body = get_body()
  if unreadable_body and runtime.conf["APPSEC_DROP_UNREADABLE_BODY"] then
    ngx.log(ngx.WARN, "Dropping request because body is unreadable and APPSEC_DROP_UNREADABLE_BODY is enabled")
    return false, runtime.conf["FALLBACK_REMEDIATION"], ngx.HTTP_FORBIDDEN, {}, nil
  end
  if body ~= nil then
    if #body > 0 then
      method = "POST"
      if headers["content-length"] == nil then
        headers["content-length"] = tostring(#body)
      end
      if headers["transfer-encoding"] ~= nil then
        headers[APPSEC_TRANSFER_ENCODING_HEADER] = headers["transfer-encoding"]
        headers["transfer-encoding"] = nil
      end
    end
  else
    headers["content-length"] = nil
  end

  local res, err = httpc:request_uri(runtime.conf["APPSEC_URL"], {
    method = method,
    headers = headers,
    body = body,
    ssl_verify = runtime.conf["SSL_VERIFY"],
  })
  httpc:close()

  if err ~= nil then
    ngx.log(ngx.ERR, "Fallback because of err: " .. err)
    return ok, remediation, status_code, {}, err
  end

  if res.status == 200 then
    ok = true
    remediation = "allow"
  elseif res.status == 403 then
    ok = false
    ngx.log(ngx.DEBUG, "Appsec body response: " .. res.body)
    local response = cjson.decode(res.body)
    remediation = response.action
    if response.http_status ~= nil then
      ngx.log(ngx.DEBUG, "Got status code from APPSEC: " .. response.http_status)
      status_code = response.http_status
    else
      status_code = ngx.HTTP_FORBIDDEN
    end
    if remediation == "challenge" then
      local appsec_response = {
        body = response.user_body_content,
        headers = response.user_headers,
        cookies = response.user_cookies,
      }
      return ok, remediation, status_code, appsec_response, nil
    end
  elseif res.status == 401 then
    ngx.log(ngx.ERR, "Unauthenticated request to APPSEC")
  else
    ngx.log(ngx.ERR, "Bad request to APPSEC (" .. res.status .. "): " .. res.body)
  end

  return ok, remediation, status_code, {}, nil

end

--- Reduces a stored release URI to something safe to put in a Location header.
--
-- A single-slash absolute path with no control characters, or "/" if it is anything
-- else. "//host/x" and "/\\host/x" are both read as an authority by a browser's URL
-- parser, and every byte ngx.redirect() refuses is a control character (measured: it
-- rejects 0-8, 10-31 and 127, all of which %c matches), so this one test covers both
-- the off-origin redirect and the 500.
--
-- Applied on read as well as on write, deliberately. The write site keeps hostile
-- values out of entries this build creates; the read site is what covers entries it
-- did not. lua_shared_dict zones are inherited across `nginx -s reload` when the name
-- and size are unchanged, so an in-place Lua upgrade leaves VERIFY_STATE entries
-- written by the previous build readable for the rest of CAPTCHA_VERIFY_TTL - and
-- before this guard existed those held the raw Referer. Checking on read also means a
-- future writer cannot reintroduce the hole by forgetting the write-site call.
--
-- Length is capped for a different reason: the entry lands in crowdsec_cache, the same
-- zone holding the decisions this bouncer exists to enforce, and its size is chosen by
-- whoever sent the request. Measured cost per bounced address, by path length: 256 B at
-- 9 bytes, 2,181 B at 1 kB, 8,325 B at 8 kB - so a long path buys 32x the dict per
-- address, and at the mint budget's ~800/s that is 6.6 MB/s into a zone a deployment
-- typically sizes at 50 MB. Full in seconds, then evicting decisions for as long as the
-- flood lasts. Rejecting rather than truncating: a truncated path is a different valid
-- page, which is a wrong destination rather than a lost one. 512 bytes is past any real
-- URL, and the cost of being over it is the return destination, never access.
local MAX_RELEASE_URI = 512

local function safe_release_uri(uri)
  if type(uri) ~= "string" then
    return "/"
  end
  if #uri > MAX_RELEASE_URI then
    return "/"
  end
  if uri ~= "/" and (uri:find("^/[^/\\]") == nil or uri:find("%c") ~= nil) then
    return "/"
  end
  return uri
end

--- return if the IP is allowed or not
-- return if the IP is allowed, false otherwise
-- the function is called from nginx access_by_lua_block
-- @param ip the IP to check
function csmod.Allow(ip)
  -- Before anything else, including the enabled checks and the location
  -- exclusions: this serves the bouncer's own self-hosted captcha widget, and a
  -- request for it must never be bounced (see captcha.ServeWidget). It is a no-op
  -- unless ALTCHA_WIDGET_FILE and ALTCHA_WIDGET_PATH are both configured.
  captcha.ServeWidget() -- serves the bundle and exits when the URI matches

  local remediationSource = flag.BOUNCER_SOURCE
  local ret_code = nil
  local remediation = ""
  local appsec_response = nil
  local ok = true
  local err = ""
  if runtime.conf["ENABLED"] ~= "false" then

    if runtime.conf["ENABLE_INTERNAL"] == "false" and ngx.req.is_internal() then
      ngx.exit(ngx.DECLINED)
    end

    if utils.table_len(runtime.conf["EXCLUDE_LOCATION"]) > 0 then
      for k, v in pairs(runtime.conf["EXCLUDE_LOCATION"]) do
        if ngx.var.uri == v then
          ngx.log(ngx.ERR, "whitelisted location: " .. v)
          ngx.exit(ngx.DECLINED)
        end
        local uri_to_check = v
        if utils.ends_with(uri_to_check, "/") == false then
          uri_to_check = uri_to_check .. "/"
        end
        if utils.starts_with(ngx.var.uri, uri_to_check) then
          ngx.log(ngx.ERR, "whitelisted location: " .. uri_to_check)
          ngx.exit(ngx.DECLINED)
        end
      end
    end

    if not is_bouncer_enabled()  then
      ngx.log(ngx.ERR, "bouncer disabled by user")
      ngx.exit(ngx.DECLINED)
    end

    ok, remediation, err = csmod.allowIp(ip)
    if err ~= nil then
      ngx.log(ngx.ERR, "[Crowdsec] bouncer error: " .. err)
    end

    -- if the ip is now allowed, try to delete its captcha state in cache
    if ok == true then
      ngx.shared.crowdsec_cache:delete("captcha_" .. ip)
    end
  end
  -- check with appSec if the remediation component doesn't have decisions for the IP
  -- OR
  -- that user configured the remediation component to always check on the appSec (even if there is a decision for the IP)
  if is_appsec_enabled() and (ok == true or is_always_send_to_appsec())  then
    local appsecOk, appsecRemediation, status_code, appsec_resp, err = csmod.AppSecCheck(ip)
    if err ~= nil then
      ngx.log(ngx.ERR, "AppSec check: " .. err)
    end
    if appsecOk == false then
      ok = false
      remediationSource = flag.APPSEC_SOURCE
      remediation = appsecRemediation
      ret_code = status_code
      appsec_response = appsec_resp
    end
  end

  local captcha_ok = runtime.captcha_ok

  -- serve one remediation for every bounced decision, whatever type the LAPI or the
  -- appsec component returned. Applied before the fallback below, so forcing captcha
  -- while the captcha provider is misconfigured still degrades to FALLBACK_REMEDIATION.
  -- `or ""` so an absent key reads as "not set" rather than as "set to nil", which
  -- would assign nil to remediation and match no arm below. Not reachable while the
  -- main config is always loaded with defaults, but the guard below it needed a
  -- default added for exactly this shape, and the two should agree.
  if not ok and (runtime.conf["OVERRIDE_REMEDIATION"] or "") ~= "" then
    -- an appsec challenge arrives with a response body, headers and cookies the
    -- challenge arm would forward; overriding it throws those away, which is
    -- documented behaviour but should never be silent behaviour
    if remediation == "challenge" and appsec_response ~= nil then
      -- INFO, not ERR: with both settings configured this is the routine outcome
      -- for every bounced request that appsec challenged, so at ERR its volume
      -- tracks attack traffic and buries the genuine errors either side of it. The
      -- same reasoning is written down at captcha.lua's insecure-context branch.
      ngx.log(ngx.INFO, "[Crowdsec] OVERRIDE_REMEDIATION discards the appsec challenge response for '" .. ip .. "'")
    end
    remediation = runtime.conf["OVERRIDE_REMEDIATION"]
  end

  if runtime.fallback ~= "" then
    -- if we can't use captcha, fallback
    -- `not captcha_ok` rather than `== false`: nil (init never completed) and false
    -- (provider unset or misconfigured) both mean there is no captcha to serve, and
    -- either shape slipping past here would skip the captcha arm below too and let
    -- the request fall through to DECLINED. OVERRIDE_REMEDIATION=captcha rewrites
    -- every decision to captcha, so that fail-open would reach bans as well.
    if remediation == "captcha" and not captcha_ok then
      remediation = runtime.fallback
    end

    -- if remediation is not supported, fallback
    if remediation ~= "captcha" and remediation ~= "ban" and remediation ~= "challenge" then
      remediation = runtime.fallback
    end
  end

  -- captcha.CanServe() as well as captcha_ok: the first is "the provider configured",
  -- the second is "this request could actually use it". Without the second, a vhost that
  -- is not a secure context reads the body and runs validateCaptcha() on every request
  -- from a bounced address, to conclude there is nothing to validate - and logs
  -- "Invalid captcha from <ip>" at ALERT for a visitor who was never offered one.
  if captcha_ok and captcha.CanServe() then
    -- if captcha can be used (configuration is valid)
    -- we check if the IP needs to validate its captcha before checking it against CrowdSec local API
    local previous_uri, flags = ngx.shared.crowdsec_cache:get("captcha_" .. ip)
    local source, state_id, err = flag.GetFlags(flags)

    if previous_uri ~= nil and state_id == flag.VERIFY_STATE then
      -- HTTP/2 and HTTP/3 requests without Content-Length cause read_body to error.
      -- Browsers reloading the captcha page send HTTP/2 GET with no Content-Length,
      -- so we skip body-reading in that case and fall through to re-serve the captcha.
      -- Genuine captcha form submissions are POSTs with Content-Length set.
      local can_read_body = not (ngx.req.http_version() >= 2 and ngx.var.http_content_length == nil)
      local args, err
      if can_read_body then
        ngx.req.read_body()
        args, err = ngx.req.get_post_args()
      else
        args = {}
      end

      if args and not err then
        local captcha_res = args[csmod.GetCaptchaBackendKey()] or 0

        if captcha_res ~= 0 then
          local valid, err = csmod.validateCaptcha(captcha_res, ip)

          if err ~= nil then
            ngx.log(ngx.ERR, "Error while validating captcha: " .. err)
          end

          if valid == true then
            -- if the captcha is valid and has been applied by the application security component
            -- then we delete the state from the cache because from the bouncing part, if the user solves the captcha
            -- we will not propose a captcha until the 'CAPTCHA_EXPIRATION'.
            -- But for the Application Security component, we serve the captcha each time the user triggers it.
            if source == flag.APPSEC_SOURCE then
              ngx.shared.crowdsec_cache:delete("captcha_" .. ip)
            else
              local succ, err, forcible = ngx.shared.crowdsec_cache:set(
                "captcha_" .. ip,
                safe_release_uri(previous_uri),
                runtime.conf["CAPTCHA_EXPIRATION"],
                bit.bor(flag.VALIDATED_STATE, source)
              )

              if not succ then
                ngx.log(ngx.ERR, "failed to add key about captcha for ip '" .. ip .. "' in cache: " .. err)
              end

              if forcible then
                ngx.log(ngx.ERR, "Lua shared dict (crowdsec cache) is full, please increase dict size in config")
              end
            end

            -- Counterpart to the "Invalid captcha from" line below: without it a
            -- solve is silent, so the logs show every failed attempt and nothing
            -- that got through. How long the IP stays released explains the quiet
            -- that follows, so it goes in the line too.
            --
            -- Resolve the destination once, so the log names where the visitor is
            -- actually going. safe_release_uri() can substitute "/" - for a
            -- pre-existing entry written before the guard existed, say - and a log line
            -- naming the rejected value while the Location says something else is the
            -- wrong thing to be reading during an incident.
            --
            -- Still scrubbed and truncated on top: the value can only reach here from a
            -- cache entry, but a pre-guard entry can carry control characters and
            -- arbitrary length, and safe_release_uri() replaces those wholesale rather
            -- than cleaning them.
            local release_uri = safe_release_uri(previous_uri)
            local logged_uri = (tostring(release_uri):gsub("%c", "?"))
            if #logged_uri > 200 then
              logged_uri = logged_uri:sub(1, 200) .. "..."
            end
            -- The appsec branch above deleted the state instead of storing it, so
            -- there is no CAPTCHA_EXPIRATION window to report there - that IP is
            -- challenged again as soon as appsec next triggers.
            local released_for = " until appsec triggers again"
            if source ~= flag.APPSEC_SOURCE then
              released_for = " for " .. runtime.conf["CAPTCHA_EXPIRATION"] .. "s"
            end
            ngx.log(ngx.ALERT, "[Crowdsec] '" .. ip .. "' solved the " ..
              runtime.conf["CAPTCHA_PROVIDER"] .. " captcha, releasing to '" ..
              logged_uri .. "'" .. released_for)

            -- captcha is valid, we redirect the IP to its previous URI using the GET method
            ngx.req.set_method(ngx.HTTP_GET)
            return ngx.redirect(release_uri)
          else
            ngx.log(ngx.ALERT, "Invalid captcha from " .. ip)
          end
        end
      end
    end
  end
  if not ok then
      if remediation == "ban" then
        ngx.log(ngx.ALERT, "[Crowdsec] denied '" .. ip .. "' with '"..remediation.."' (by " .. flag.Flags[remediationSource] .. ")")
        ban.apply(ret_code)
        return
      end
      if remediation == "challenge" then
        if appsec_response ~= nil then
          ngx.log(ngx.DEBUG, "[Crowdsec] challenge '" .. ip .. "' (by " .. flag.Flags[remediationSource] .. ")")
          challenge.apply(ret_code, appsec_response.body, appsec_response.headers, appsec_response.cookies)
          return
        else
          ngx.log(ngx.ERR, "[Crowdsec] challenge remediation for '" .. ip .. "' but no response data, falling back to ban")
          ban.apply(ret_code)
          return
        end
      end
      -- if the remediation is a captcha and captcha is well configured
      if remediation == "captcha" and captcha_ok and ngx.var.uri ~= "/favicon.ico" then
          local previous_uri, flags = ngx.shared.crowdsec_cache:get("captcha_"..ip)
          local source, state_id, err = flag.GetFlags(flags)
          -- we check if the IP is already in cache for captcha and not yet validated
          if previous_uri == nil or state_id ~= flag.VALIDATED_STATE or remediationSource == flag.APPSEC_SOURCE then 
              local uri = ngx.var.uri
              if ngx.req.get_method() ~= "GET" then
                -- A non-GET has no page of its own to return to: ngx.var.uri is the
                -- endpoint the form posted to, and a GET to that after the solve is
                -- often a 405. Keep whatever the GET that opened this flow recorded,
                -- so a failed solve does not cost the visitor their destination - the
                -- captcha form posts to itself, so a wrong answer lands here and would
                -- otherwise overwrite the entry.
                --
                -- On an appsec re-challenge the entry may already be VALIDATED from
                -- an earlier, finished flow, so the value carried forward can predate
                -- the request being served. It is always a path this same visitor
                -- asked for, so that is a stale destination rather than a wrong one.
                --
                -- Upstream read the Referer here instead. That is client-chosen and
                -- this value goes straight into a Location header on the next solve,
                -- which made it an open redirect; it is also suppressed outright by
                -- Referrer-Policy: no-referrer, so it was never reliable. Reading the
                -- stored value instead means everything in this entry originated from
                -- ngx.var.uri or the literal "/" - no client input, so nothing to
                -- validate and no parser to get wrong.
                uri = previous_uri or "/"
              end

              -- $uri is nginx-normalised but percent-DECODED, so it is still the
              -- client's bytes and the only thing that made it look safe was where it
              -- came from. "/%5cevil.example/x" decodes to "/\\evil.example/x", and a
              -- browser's URL parser treats a backslash as a solidus for special
              -- schemes, so that Location is read as "//evil.example/x" - off-origin,
              -- which is the redirect this whole path was cleaned up to prevent.
              -- "%0d%0a" decodes to bytes ngx.redirect() refuses outright, turning the
              -- response that releases the visitor into a 500. nginx collapses a real
              -- "//" itself, so the backslash is the shape that gets this far.
              --
              -- Guarded here rather than at the redirect because this is the only
              -- writer of the entry: the VALIDATED_STATE write on a successful solve
              -- carries this value forward, so cleaning it once keeps the cache itself
              -- free of anything hostile and every reader inherits that.
              local safe_uri = safe_release_uri(uri)
              if safe_uri ~= uri then
                ngx.log(ngx.NOTICE, "[Crowdsec] unusable release URI for '" .. ip ..
                  "', releasing to '/' instead")
              end
              uri = safe_uri

              -- Only once we know a captcha is actually going out. captcha.apply()
              -- below decides that too, and if it decides no, this entry would be a
              -- 300s attacker-paced write into the decision cache's own dict for a page
              -- the visitor never saw - repeated on every request from that address.
              -- apply() already protects the mint budget from this; the dict write and
              -- the body read on the next request are the more expensive halves.
              local succ, err, forcible = true, nil, false
              if captcha.CanServe() then
                succ, err, forcible = ngx.shared.crowdsec_cache:set("captcha_"..ip, uri , CAPTCHA_VERIFY_TTL, bit.bor(flag.VERIFY_STATE, remediationSource))
              end
              if not succ then
                ngx.log(ngx.ERR, "failed to add key about captcha for ip '" .. ip .. "' in cache: "..err)
              end
              if forcible then
                ngx.log(ngx.ERR, "Lua shared dict (crowdsec cache) is full, please increase dict size in config")
              end
              ngx.log(ngx.ALERT, "[Crowdsec] denied '" .. ip .. "' with '"..remediation.."'")
              -- ret_code goes with it so that if the captcha cannot be served and
              -- this degrades to a ban, it carries the same status the ban arms
              -- above would have used.
              captcha.apply(ip, ret_code)
              return
          end
      end
  end
  ngx.exit(ngx.DECLINED)
end



-- Use it if you are able to close at shuttime
function csmod.close()
end

return csmod

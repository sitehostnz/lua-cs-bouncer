local utils = require "plugins.crowdsec.utils"


local M = {_TYPE='module', _NAME='ban.funcs', _VERSION='1.0-0'}

M.template_str = ""
M.redirect_location = ""
M.ret_code = ngx.HTTP_FORBIDDEN


function M.new(template_path, redirect_location, ret_code)
    M.redirect_location = redirect_location

    ret_code_ok = false
    if ret_code ~= nil and ret_code ~= 0 and ret_code ~= "" then
        for k, v in pairs(utils.HTTP_CODE) do
            if k == ret_code then
                M.ret_code = utils.HTTP_CODE[ret_code]
                ret_code_ok = true
                break
            end
        end
        if ret_code_ok == false then
            ngx.log(ngx.ERR, "RET_CODE '" .. ret_code .. "' is not supported, using default HTTP code " .. M.ret_code)
        end
    end

    template_file_ok = false
    if (template_path ~= nil and template_path ~= "" and utils.file_exist(template_path) == true) then
        M.template_str = utils.read_file(template_path)
        if M.template_str ~= nil then
            template_file_ok = true
        end
    end

    if template_file_ok == false and (M.redirect_location == nil or M.redirect_location == "") then
        ngx.log(ngx.ERR, "BAN_TEMPLATE_PATH and REDIRECT_LOCATION variable are empty, will return HTTP " .. M.ret_code  .. " for ban decisions")
    end

    return nil
end



function M.apply(...)
    local args = {...}
    local ret_code = args[1]

    ngx.log(ngx.DEBUG, "args:" .. tostring(args[1]))

    local status = 0
    if ret_code ~= nil then
        status = ret_code
    else
        status = M.ret_code
    end

    ngx.log(ngx.DEBUG, "BAN: status=" .. status .. ", redirect_location=" .. M.redirect_location .. ", template_str=" .. M.template_str)
    if M.redirect_location ~= "" then
        ngx.redirect(M.redirect_location)
        return
    end

    -- Per-vhost override: the file named by `set $crowdsec_ban_template <path>;`
    -- in the vhost's server block, following the $crowdsec_enable_bouncer pattern.
    -- Read on every ban rather than cached - one small page-cache-warm read, the
    -- same cost nginx pays serving any static file - so an edited page takes
    -- effect immediately, with no reload and nothing to invalidate. Deliberately
    -- checked after the redirect: a global REDIRECT_LOCATION is instance-wide
    -- policy and a host's page must not silently defeat it. Falls back to the
    -- global template, so a vhost that never sets the variable, or sets a path
    -- whose file does not exist yet, keeps working unchanged.
    local body = utils.template_override(ngx.var.crowdsec_ban_template) or M.template_str

    if body ~= "" then
        ngx.header.content_type = "text/html"
        ngx.header.cache_control = "no-cache"
        ngx.status = status
        ngx.say(body)
        ngx.exit(status)
        return
    end
 
    ngx.exit(status)

    return
end

return M

local template = {}

function template.compile(template_str, args)

    for k, v in pairs(args) do
        local var = "{{" .. k .. "}}"
        -- The value goes in the replacement position, where Lua reads '%' followed
        -- by a digit as a capture reference and raises "invalid capture index" on
        -- anything else - lazily, only when the placeholder is actually present. Every
        -- value here is operator-supplied config, and this runs inside init_by_lua, so
        -- one stray '%' in one setting stops nginx starting on every vhost. Escaped
        -- once here rather than guarded per setting. Parenthesised so gsub's second
        -- return value does not become a third argument to the outer gsub.
        template_str = template_str:gsub(var, (tostring(v):gsub("%%", "%%%%")))
    end

    return template_str
end

return template
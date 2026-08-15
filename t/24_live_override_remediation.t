# OVERRIDE_REMEDIATION=captcha.
# The LAPI returns a "ban" decision, so without the override the bouncer would serve
# the ban template with 403. With it, the request is challenged with a captcha instead.

use Test::Nginx::Socket 'no_plan';

run_tests();

__DATA__

=== TEST 24: ban decision forced to captcha

--- main_config
load_module /usr/share/nginx/modules/ndk_http_module.so;
load_module /usr/share/nginx/modules/ngx_http_lua_module.so;

--- http_config

lua_package_path './lib/?.lua;;';
lua_shared_dict crowdsec_cache 50m;
lua_shared_dict crowdsec_altcha 10m;
lua_ssl_trusted_certificate /etc/ssl/certs/ca-certificates.crt;

init_by_lua_block
{
        cs = require "crowdsec"
        local ok, err = cs.init("./t/conf_t/24_live_override_remediation_crowdsec_nginx_bouncer.conf", "crowdsec-nginx-bouncer/v1.0.8")
        if ok == nil then
                ngx.log(ngx.ERR, "[Crowdsec] " .. err)
                error()
        end
        ngx.log(ngx.ALERT, "[Crowdsec] Initialisation done")
}

access_by_lua_block {
        local cs = require "crowdsec"
        cs.Allow(ngx.var.remote_addr)
}

server {
    listen 8081;

      location = /v1/decisions {
            content_by_lua_block {
            local args, err = ngx.req.get_uri_args()
            if args.ip == "1.1.1.1" then
               ngx.say('[{"duration":"1h00m00s","id":4091593,"origin":"CAPI","scenario":"crowdsecurity/vpatch-CVE-2024-4577","scope":"Ip","type":"ban","value":"1.1.1.1"}]')
            else
               -- 'null' via print, not '[{}]' via say: an empty decision object
               -- reaches live.lua as a table with no fields and 500s the request
               -- concatenating decision.type, and live.lua compares the body to
               -- "null" exactly, so say's trailing newline would never match
               ngx.print('null')
            end
            }
      }
}

--- config

location = /t {
    set_real_ip_from 127.0.0.1;
    real_ip_header   X-Forwarded-For;
    real_ip_recursive on;
    content_by_lua_block {
        ngx.print("ok")
    }
}

--- more_headers
X-Forwarded-For: 1.1.1.1

--- request
GET /t

--- error_code: 200
--- response_body_like: <title>CrowdSec Captcha</title>
--- no_error_log
[Crowdsec] denied '1.1.1.1' with 'ban'



=== TEST 24b: captcha decision forced to ban

The other direction, which tightens rather than loosens: the LAPI returns a captcha
decision and the override turns it into a ban. BAN_TEMPLATE_PATH points at nothing,
so ban.apply() falls through to a bare 403.

--- main_config
load_module /usr/share/nginx/modules/ndk_http_module.so;
load_module /usr/share/nginx/modules/ngx_http_lua_module.so;

--- http_config

lua_package_path './lib/?.lua;;';
lua_shared_dict crowdsec_cache 50m;
lua_shared_dict crowdsec_altcha 10m;
lua_ssl_trusted_certificate /etc/ssl/certs/ca-certificates.crt;

init_by_lua_block
{
        cs = require "crowdsec"
        local ok, err = cs.init("./t/conf_t/24b_override_ban_crowdsec_nginx_bouncer.conf", "crowdsec-nginx-bouncer/v1.0.8")
        if ok == nil then
                ngx.log(ngx.ERR, "[Crowdsec] " .. err)
                error()
        end
        ngx.log(ngx.ALERT, "[Crowdsec] Initialisation done")
}

access_by_lua_block {
        local cs = require "crowdsec"
        cs.Allow(ngx.var.remote_addr)
}

server {
    listen 8081;

      location = /v1/decisions {
            content_by_lua_block {
            local args, err = ngx.req.get_uri_args()
            if args.ip == "1.1.1.1" then
               ngx.say('[{"duration":"1h00m00s","id":4091593,"origin":"CAPI","scenario":"crowdsecurity/vpatch-CVE-2024-4577","scope":"Ip","type":"captcha","value":"1.1.1.1"}]')
            else
               ngx.print('null')
            end
            }
      }
}

--- config

location = /t {
    set_real_ip_from 127.0.0.1;
    real_ip_header   X-Forwarded-For;
    real_ip_recursive on;
    content_by_lua_block {
        ngx.print("ok")
    }
}

--- more_headers
X-Forwarded-For: 1.1.1.1

--- request
GET /t

--- error_code: 403
--- error_log
[Crowdsec] denied '1.1.1.1' with 'ban'



=== TEST 24c: an unsupported override value is ignored

config.lua rejects anything that is not captcha or ban and falls back to empty, which
means "honour the decision as received". Without that, an arbitrary string would reach
the remediation checks, match none of them, and send every bounced request to
FALLBACK_REMEDIATION - quietly turning a typo into a site-wide ban.

--- main_config
load_module /usr/share/nginx/modules/ndk_http_module.so;
load_module /usr/share/nginx/modules/ngx_http_lua_module.so;

--- http_config

lua_package_path './lib/?.lua;;';
lua_shared_dict crowdsec_cache 50m;
lua_shared_dict crowdsec_altcha 10m;
lua_ssl_trusted_certificate /etc/ssl/certs/ca-certificates.crt;

init_by_lua_block
{
        cs = require "crowdsec"
        local ok, err = cs.init("./t/conf_t/24c_override_invalid_crowdsec_nginx_bouncer.conf", "crowdsec-nginx-bouncer/v1.0.8")
        if ok == nil then
                ngx.log(ngx.ERR, "[Crowdsec] " .. err)
                error()
        end
        ngx.log(ngx.ALERT, "[Crowdsec] Initialisation done")
}

access_by_lua_block {
        local cs = require "crowdsec"
        cs.Allow(ngx.var.remote_addr)
}

server {
    listen 8081;

      location = /v1/decisions {
            content_by_lua_block {
            local args, err = ngx.req.get_uri_args()
            if args.ip == "1.1.1.1" then
               ngx.say('[{"duration":"1h00m00s","id":4091593,"origin":"CAPI","scenario":"crowdsecurity/vpatch-CVE-2024-4577","scope":"Ip","type":"captcha","value":"1.1.1.1"}]')
            else
               ngx.print('null')
            end
            }
      }
}

--- config

location = /t {
    set_real_ip_from 127.0.0.1;
    real_ip_header   X-Forwarded-For;
    real_ip_recursive on;
    content_by_lua_block {
        ngx.print("ok")
    }
}

--- more_headers
X-Forwarded-For: 1.1.1.1

--- request
GET /t

--- error_code: 200
--- response_body_like: <title>CrowdSec Captcha</title>
--- error_log
unsupported value 'not-a-remediation' for variable 'OVERRIDE_REMEDIATION'
--- no_error_log
[Crowdsec] denied '1.1.1.1' with 'ban'



=== TEST 24d: forcing captcha with an unusable provider still degrades to the fallback

The ordering the override was designed around: it is applied before the fallback, so
OVERRIDE_REMEDIATION=captcha against a captcha provider that failed to configure ends
up serving FALLBACK_REMEDIATION rather than a captcha page nobody can solve.

This is the case worth pinning, because getting it wrong fails open rather than
closed: if the fallback stopped firing, remediation would stay "captcha" while
captcha_ok was false, every branch in Allow() would decline to handle it, and the
bounced request would be let through with a 200.

The LAPI returns "ban" here rather than "captcha" deliberately. Against a captcha
decision the override rewrites captcha to captcha, a no-op, and the 403 below would
come entirely from the pre-existing fallback - the test would pass with the whole
OVERRIDE_REMEDIATION block deleted. Starting from "ban" makes the ordering
load-bearing: applied before the fallback, as it is, the override turns it into
"captcha", the fallback turns that back into "ban", and the request is denied.
Applied after, "captcha" would survive with captcha_ok false and reach the 200.

What this does not pin is the override existing at all - without it the decision is
already "ban" and still 403. TEST 24 covers that direction.

--- main_config
load_module /usr/share/nginx/modules/ndk_http_module.so;
load_module /usr/share/nginx/modules/ngx_http_lua_module.so;

--- http_config

lua_package_path './lib/?.lua;;';
lua_shared_dict crowdsec_cache 50m;
lua_shared_dict crowdsec_altcha 10m;
lua_ssl_trusted_certificate /etc/ssl/certs/ca-certificates.crt;

init_by_lua_block
{
        cs = require "crowdsec"
        local ok, err = cs.init("./t/conf_t/24d_override_captcha_broken_provider_crowdsec_nginx_bouncer.conf", "crowdsec-nginx-bouncer/v1.0.8")
        if ok == nil then
                ngx.log(ngx.ERR, "[Crowdsec] " .. err)
                error()
        end
        ngx.log(ngx.ALERT, "[Crowdsec] Initialisation done")
}

access_by_lua_block {
        local cs = require "crowdsec"
        cs.Allow(ngx.var.remote_addr)
}

server {
    listen 8081;

      location = /v1/decisions {
            content_by_lua_block {
            local args, err = ngx.req.get_uri_args()
            if args.ip == "1.1.1.1" then
               ngx.say('[{"duration":"1h00m00s","id":4091593,"origin":"CAPI","scenario":"crowdsecurity/vpatch-CVE-2024-4577","scope":"Ip","type":"ban","value":"1.1.1.1"}]')
            else
               ngx.print('null')
            end
            }
      }
}

--- config

location = /t {
    set_real_ip_from 127.0.0.1;
    real_ip_header   X-Forwarded-For;
    real_ip_recursive on;
    content_by_lua_block {
        ngx.print("ok")
    }
}

--- more_headers
X-Forwarded-For: 1.1.1.1

--- request
GET /t

--- error_code: 403
--- error_log eval
[
"error loading captcha plugin: unsupported captcha provider 'not-a-provider'",
"[Crowdsec] denied '1.1.1.1' with 'ban'",
]



=== TEST 24e: the fallback the override leans on survives an absent config line

24d with FALLBACK_REMEDIATION removed from the file, which every other fixture in
this suite sets. It has to come from the default in config.lua instead.

Without that default runtime.fallback is nil rather than "ban", and nil is not "",
so the fallback block still runs and assigns nil to remediation. Nothing downstream
matches nil - not the ban arm, not challenge, not captcha - so Allow() falls through
to ngx.exit(ngx.DECLINED) and serves the request. That is the whole failure: a
bouncer with a broken captcha provider and one missing config line stops bouncing,
and the only symptom is a 200 where a 403 belonged.

--- main_config
load_module /usr/share/nginx/modules/ndk_http_module.so;
load_module /usr/share/nginx/modules/ngx_http_lua_module.so;

--- http_config

lua_package_path './lib/?.lua;;';
lua_shared_dict crowdsec_cache 50m;
lua_shared_dict crowdsec_altcha 10m;
lua_ssl_trusted_certificate /etc/ssl/certs/ca-certificates.crt;

init_by_lua_block
{
        cs = require "crowdsec"
        local ok, err = cs.init("./t/conf_t/24e_override_no_fallback_crowdsec_nginx_bouncer.conf", "crowdsec-nginx-bouncer/v1.0.8")
        if ok == nil then
                ngx.log(ngx.ERR, "[Crowdsec] " .. err)
                error()
        end
        ngx.log(ngx.ALERT, "[Crowdsec] Initialisation done")
}

access_by_lua_block {
        local cs = require "crowdsec"
        cs.Allow(ngx.var.remote_addr)
}

server {
    listen 8081;

      location = /v1/decisions {
            content_by_lua_block {
            local args, err = ngx.req.get_uri_args()
            if args.ip == "1.1.1.1" then
               ngx.say('[{"duration":"1h00m00s","id":4091593,"origin":"CAPI","scenario":"crowdsecurity/vpatch-CVE-2024-4577","scope":"Ip","type":"ban","value":"1.1.1.1"}]')
            else
               ngx.print('null')
            end
            }
      }
}

--- config

location = /t {
    set_real_ip_from 127.0.0.1;
    real_ip_header   X-Forwarded-For;
    real_ip_recursive on;
    content_by_lua_block {
        ngx.print("ok")
    }
}

--- more_headers
X-Forwarded-For: 1.1.1.1

--- request
GET /t

--- error_code: 403
--- response_body_unlike: ok
--- error_log
[Crowdsec] denied '1.1.1.1' with 'ban'



=== TEST 24f: an evicted captcha_ok flag bans rather than letting the request through

captcha_ok is written to crowdsec_cache at init with no TTL, in the same dict that
holds every decision - so it can be evicted under memory pressure. When it is, the
flag reads nil, which is neither the true it was nor the false a broken provider
would give.

nil is the case worth pinning because it used to fail open. The fallback test was
`captcha_ok == false`, which nil does not satisfy, so remediation stayed "captcha";
the captcha arm further down tests captcha_ok for truthiness, so nil skipped that
too; and with nothing left to handle it, Allow() reached ngx.exit(ngx.DECLINED) and
served a request the LAPI had asked to be captcha'd. Testing `not captcha_ok` instead
treats an absent flag like a broken one and falls back to FALLBACK_REMEDIATION.

Every other fixture reaches that line with a genuine false, via an unusable
CAPTCHA_PROVIDER, and against false the two forms are indistinguishable - so without
this block the change could be reverted with the whole suite still green. The dict is
poked directly, the way t/25 reads it directly, because eviction cannot be provoked
on demand.

--- main_config
load_module /usr/share/nginx/modules/ndk_http_module.so;
load_module /usr/share/nginx/modules/ngx_http_lua_module.so;

--- http_config

lua_package_path './lib/?.lua;;';
lua_shared_dict crowdsec_cache 50m;
lua_shared_dict crowdsec_altcha 10m;
lua_ssl_trusted_certificate /etc/ssl/certs/ca-certificates.crt;

init_by_lua_block
{
        cs = require "crowdsec"
        local ok, err = cs.init("./t/conf_t/24f_captcha_ok_evicted_crowdsec_nginx_bouncer.conf", "crowdsec-nginx-bouncer/v1.0.8")
        if ok == nil then
                ngx.log(ngx.ERR, "[Crowdsec] " .. err)
                error()
        end
        ngx.log(ngx.ALERT, "[Crowdsec] Initialisation done")
}

access_by_lua_block {
        local cs = require "crowdsec"
        cs.Allow(ngx.var.remote_addr)
}

server {
    listen 8081;

      location = /v1/decisions {
            content_by_lua_block {
            local args, err = ngx.req.get_uri_args()
            if args.ip == "1.1.1.1" then
               ngx.say('[{"duration":"1h00m00s","id":4091593,"origin":"CAPI","scenario":"crowdsecurity/vpatch-CVE-2024-4577","scope":"Ip","type":"captcha","value":"1.1.1.1"}]')
            else
               ngx.print('null')
            end
            }
      }
}

--- config

location = /t {
    set_real_ip_from 127.0.0.1;
    real_ip_header   X-Forwarded-For;
    real_ip_recursive on;
    content_by_lua_block {
        ngx.print("ok")
    }
}

# Test-only. Asserting on the flag being present first means a rename of the cache key
# turns this into a failure rather than a test that silently stops evicting anything.
location = /_evict {
    content_by_lua_block {
        local was = ngx.shared.crowdsec_cache:get("captcha_ok")
        ngx.shared.crowdsec_cache:delete("captcha_ok")
        ngx.print(tostring(was) .. "/" .. tostring(ngx.shared.crowdsec_cache:get("captcha_ok")))
    }
}

--- init

use LWP::UserAgent;
my $ua = LWP::UserAgent->new(timeout => 10);
my $r = $ua->get('http://127.0.0.1:1984/_evict');
if (!$r->is_success || $r->decoded_content ne 'true/nil') {
    open my $fh, '>', 't/servroot/logs/perl.init.log' or die $!;
    print $fh "expected captcha_ok to be true then deleted, got '"
        . $r->decoded_content . "' (HTTP " . $r->code . ")\n";
    close $fh;
    exit 1;
}

--- more_headers
X-Forwarded-For: 1.1.1.1

--- request
GET /t

--- error_code: 403
--- response_body_unlike: ok
--- error_log
[Crowdsec] denied '1.1.1.1' with 'ban'

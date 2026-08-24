# The altcha widget bundle, served by the bouncer itself.
#
# By default the captcha page loads altcha.js from a CDN, so a visitor whose
# network cannot reach jsdelivr is served a captcha with no widget on it and has
# no way through. ALTCHA_WIDGET_FILE + ALTCHA_WIDGET_PATH read the bundle at init
# and answer it from captcha.ServeWidget(), called at the top of csmod.Allow().
#
# Serving it from there rather than from an nginx location block is the whole
# design, for three reasons this file pins:
#
#   * one http-level access_by_lua_block covers every vhost, so nothing has to be
#     added per server block - note there is no location for the widget path below
#   * the browser fetching the script is an address being captcha'd, and every
#     other request from such an address is answered with the captcha page. Served
#     before the remediation logic, the script arrives as a script
#   * serving the captcha page also rewrites the URI the visitor is released to.
#     A bounced subresource fetch would send them to the .js file after solving,
#     which is the trap /favicon.ico is exempt from
#
# The bundle is also compared byte for byte: the stub ends on a semicolon with no
# trailing newline, which utils.read_file() would have eaten.

use Test::Nginx::Socket 'no_plan';

run_tests();

__DATA__

=== TEST 29: the bouncer serves the widget, and serving it does not bounce

--- init

use LWP::UserAgent;

my $ua = LWP::UserAgent->new(timeout => 10);
my $base = 'http://127.0.0.1:1984';

open my $out_fh, '>', 't/servroot/logs/perl.init.log' or die $!;

sub fail {
    print $out_fh "$_[0]\n";
    exit 1;
}

sub as_bounced {
    my ($path) = @_;
    my $req = HTTP::Request->new(GET => $base . $path);
    $req->header('X-Forwarded-For' => '1.1.1.1');
    return $ua->request($req);
}

# probed without X-Forwarded-For, so it arrives as 127.0.0.1 and the LAPI stub
# declines to bounce it
sub released_to {
    my $r = $ua->get($base . '/_dict?key=captcha_1.1.1.1');
    fail("could not read the decision cache: HTTP " . $r->code) unless $r->is_success;
    return $r->decoded_content;
}

# --- the captcha page must advertise the local copy ---------------------------
my $page = as_bounced('/t');
fail("expected the captcha page, got HTTP " . $page->code) unless $page->code == 200;
my $html = $page->decoded_content;

fail("the page does not point at the self-hosted widget")
    unless $html =~ m{<script async defer type="module" src="/\.crowdsec/altcha-test\.js"></script>};
fail("the page still loads the widget from the CDN")
    if $html =~ m{<script[^>]*src="https://cdn\.jsdelivr\.net};
# integrity is for a third party we no longer have, and a stale hash would fail
# silently - the element simply never upgrades
fail("the self-hosted script tag still carries an integrity attribute")
    if $html =~ m{src="/\.crowdsec[^>]*integrity=};

# the visitor is released to /t at this point
fail("expected to be released to /t, cache says: " . released_to())
    unless released_to() eq 'present:/t';

# --- fetching the widget must yield the widget -------------------------------
my $js = as_bounced('/.crowdsec/altcha-test.js');
fail("the widget fetch was answered with HTTP " . $js->code) unless $js->code == 200;
fail("the widget fetch was answered with the captcha page")
    if $js->decoded_content =~ /<altcha-widget|<!DOCTYPE/i;

open my $stub_fh, '<', 't/assets_t/altcha-stub.js' or die $!;
binmode $stub_fh;
my $stub = do { local $/; <$stub_fh> };
close $stub_fh;

# byte for byte: a reader that dropped the final ';' would pass every other
# assertion here and ship a broken bundle
fail("the served bundle differs from the file on disk (" . length($js->content)
   . " bytes served, " . length($stub) . " on disk)")
    unless $js->content eq $stub;

fail("wrong content type: " . ($js->header('Content-Type') // 'none'))
    unless ($js->header('Content-Type') // '') =~ m{^application/javascript};
fail("the bundle is not cacheable: " . ($js->header('Cache-Control') // 'none'))
    unless ($js->header('Cache-Control') // '') =~ /immutable/;

# --- and must not have moved the visitor's destination -----------------------
# The assertion this file exists for. Bounced, this fetch would have rewritten the
# release URI to the script, so solving would send the visitor to a .js file.
fail("fetching the widget moved the release URI, cache says: " . released_to())
    unless released_to() eq 'present:/t';

print $out_fh "Widget advertised, served byte-exact, release URI intact.\n";
close $out_fh or warn "Could not close filehandle: $!";

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
        local ok, err = cs.init("./t/conf_t/29_self_hosted_widget_crowdsec_nginx_bouncer.conf", "crowdsec-nginx-bouncer/v1.0.8")
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

# Note what is absent: no location for /.crowdsec/. The bundle is served from the
# access phase, which is why this works on every vhost without a location block.
location = /t {
    set_real_ip_from 127.0.0.1;
    real_ip_header   X-Forwarded-For;
    real_ip_recursive on;
    content_by_lua_block {
        ngx.print("PROTECTED")
    }
}

# Test-only white-box read of the decision cache, to assert on the URI the visitor
# is released to after solving.
location = /_dict {
    content_by_lua_block {
        local key = ngx.req.get_uri_args()["key"]
        local v = ngx.shared.crowdsec_cache:get(key)
        ngx.print(v == nil and "absent" or ("present:" .. tostring(v)))
    }
}

--- more_headers
X-Forwarded-For: 1.1.1.1

--- request
GET /.crowdsec/altcha-test.js

--- error_code: 200
--- response_body_like: customElements\.define\("altcha-widget"
--- response_headers
Content-Type: application/javascript; charset=utf-8
Content-Length: 368
--- no_error_log
serving the widget from the CDN instead



=== TEST 29b: with the keys unset, the CDN copy is used exactly as before

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
        local ok, err = cs.init("./t/conf_t/29b_cdn_widget_crowdsec_nginx_bouncer.conf", "crowdsec-nginx-bouncer/v1.0.8")
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
        ngx.print("PROTECTED")
    }
}

--- more_headers
X-Forwarded-For: 1.1.1.1

--- request
GET /t

--- error_code: 200
--- response_body_like: integrity="sha256-[A-Za-z0-9+/=]+" crossorigin="anonymous"
--- no_error_log
serving the altcha widget from



=== TEST 29c: an unreadable bundle is reported and falls back to the CDN

A visitor who can reach jsdelivr is better off than one served a captcha page with
no widget on it, so a bundle that cannot be read must not take the provider down -
it degrades to the CDN copy, loudly.

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
        local ok, err = cs.init("./t/conf_t/29c_unreadable_widget_crowdsec_nginx_bouncer.conf", "crowdsec-nginx-bouncer/v1.0.8")
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
        ngx.print("PROTECTED")
    }
}

--- more_headers
X-Forwarded-For: 1.1.1.1

--- request
GET /t

--- error_code: 200
--- response_body_like: cdn\.jsdelivr\.net
--- error_log
cannot be read, serving the widget from the CDN instead


=== TEST 29d: a percent sign in the widget path is refused, and nginx still starts

ALTCHA_WIDGET_PATH is interpolated into the script tag and that string goes through
template.compile(), which does template_str:gsub(var, v) with this value in the
replacement position. Lua reads '%' there as a capture reference, so anything but
'%%' raises - and this runs inside csmod.init() inside init_by_lua, so unguarded it
does not degrade the provider, it stops nginx starting on every vhost. A
percent-encoded path is a plausible thing to paste in, since that is the form a
browser address bar shows.

That this block runs at all is most of the assertion: nginx came up. The rest pins
the failure landing where its neighbours land - a line in the log and the CDN copy -
rather than anywhere new. Nothing is lost by refusing it either, because
ServeWidget() compares the path against ngx.var.uri, which nginx has already
percent-decoded, so it could never have matched a request.

The integrity attribute below is the CDN shape 29b asserts for an unset pair, so it
is also what "fell back" looks like from the page.

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
        local ok, err = cs.init("./t/conf_t/29d_widget_path_percent_crowdsec_nginx_bouncer.conf", "crowdsec-nginx-bouncer/v1.0.8")
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
        ngx.print("PROTECTED")
    }
}

--- more_headers
X-Forwarded-For: 1.1.1.1

--- request
GET /t

--- error_code: 200
--- response_body_like: integrity="sha256-[A-Za-z0-9+/=]+" crossorigin="anonymous"
--- error_log
must not contain '%', '?' or '#', serving the widget from the CDN instead


=== TEST 29e: a percent sign in a config value reaching a template does not stop nginx

template.compile() puts every value from template_data in the replacement position of a
gsub, where Lua reads '%' followed by a digit as a capture reference and raises "invalid
capture index" on anything else - lazily, only when the placeholder is actually present.
Every one of those values is operator-supplied configuration, and this runs inside
init_by_lua, so one stray '%' in one setting stops nginx starting on every vhost.

29d covers the same failure for ALTCHA_WIDGET_PATH, but it covers it by refusing the
value before it is interpolated, which means the escaping in template.compile() itself is
exercised by nothing. This block is the one that pins the escaping: SITE_KEY is unused by
altcha but is still substituted, and t/assets_t/captcha_sitekey.html is a minimal template
that references it.

SITE_KEY is 'a%2b' rather than 'a%b' on purpose: Lua only raises for '%' followed by a
digit ("invalid capture index"), and silently drops the '%' otherwise - measured, 'a%b'
renders as 'ab'. The digit form is the one that stops nginx starting, so it is the one
worth pinning; the silent-corruption form fails the same body assertion anyway.

That this block runs at all is most of the assertion - nginx came up. The body check is
the rest: the percent has to survive into the page literally, not as a capture reference
and not doubled.

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
        local ok, err = cs.init("./t/conf_t/29e_sitekey_percent_crowdsec_nginx_bouncer.conf", "crowdsec-nginx-bouncer/v1.0.8")
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
               ngx.say('[{"duration":"1h00m00s","id":4091595,"origin":"CAPI","scenario":"crowdsecurity/vpatch-CVE-2024-4577","scope":"Ip","type":"captcha","value":"1.1.1.1"}]')
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
        ngx.print("PROTECTED")
    }
}

--- more_headers
X-Forwarded-For: 1.1.1.1

--- request
GET /t

--- error_code: 200
--- response_body_like: <p id="sitekey">a%2b</p>

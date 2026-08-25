# Per-vhost template overrides via nginx variables.
#
# A generated config can point any vhost at its own pages with
#     set $crowdsec_ban_template              <path>;
#     set $crowdsec_captcha_template          <path>;
#     set $crowdsec_captcha_insecure_template <path>;
# following the $crowdsec_enable_bouncer pattern. The variables are optional: a
# vhost that never sets one, sets it empty, or names a file that does not exist
# (the normal state - a generated config names the path for every vhost, only
# hosts whose operator uploaded a page have one) falls back to the global template
# from the bouncer config. Files are read per serve, so page edits take effect
# without a reload.
#
# The captcha override is the interesting one: it is compiled per serve and, for
# altcha, must carry exactly one widget slot - a broken page degrades to the stock
# captcha, loudly, rather than to a widget that cannot work.
#
# The one hostile input: `set` interpolates runtime variables, so a config that
# splices $host into the path hands the client a say in it. Overrides containing
# '..' are refused for exactly that case.
#
# The locations here stand in for vhosts: overrides hang off `set` in the config,
# so a location apiece is enough - no Host routing needed except in the insecure
# block, where a non-loopback Host is what makes the request insecure at all.

use Test::Nginx::Socket 'no_plan';

run_tests();

__DATA__

=== TEST 28: per-vhost ban page, with every fallback

--- init

use LWP::UserAgent;

my $ua = LWP::UserAgent->new(timeout => 10);

open my $out_fh, '>', 't/servroot/logs/perl.init.log' or die $!;

sub fail {
    print $out_fh "$_[0]\n";
    exit 1;
}

sub banned_body {
    my ($path) = @_;
    my $req = HTTP::Request->new(GET => "http://127.0.0.1:1984$path");
    $req->header('X-Forwarded-For' => '1.1.1.1');
    my $resp = $ua->request($req);
    fail("$path: expected the ban status 403, got HTTP " . $resp->code)
        unless $resp->code == 403;
    return $resp->decoded_content;
}

# the vhost's own page
fail("/t was not served the vhost override")
    unless banned_body('/t') =~ /VHOST-A BAN PAGE/;

# override set but the file does not exist yet: the normal state for a host whose
# operator has not uploaded a page - must fall back to the global template
fail("/u did not fall back to the global template")
    unless banned_body('/u') =~ /GLOBAL BAN PAGE/;

# no override set at all
fail("/v did not serve the global template")
    unless banned_body('/v') =~ /GLOBAL BAN PAGE/;

# a path containing '..' is refused even though the file it reaches exists -
# the case where a config interpolated something client-controlled into the path
my $w = banned_body('/w');
fail("/w served a '..' path instead of refusing it") if $w =~ /VHOST-A BAN PAGE/;
fail("/w did not fall back to the global template") unless $w =~ /GLOBAL BAN PAGE/;

print $out_fh "Override, both fallbacks and the '..' refusal all served.\n";
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
        local ok, err = cs.init("./t/conf_t/28_per_vhost_templates_crowdsec_nginx_bouncer.conf", "crowdsec-nginx-bouncer/v1.0.8")
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
    set $crowdsec_ban_template ./t/vhosts_t/ban_a.html;
    set_real_ip_from 127.0.0.1;
    real_ip_header   X-Forwarded-For;
    real_ip_recursive on;
    content_by_lua_block {
        ngx.print("ok")
    }
}

location = /u {
    set $crowdsec_ban_template ./t/vhosts_t/no-such-page.html;
    set_real_ip_from 127.0.0.1;
    real_ip_header   X-Forwarded-For;
    real_ip_recursive on;
    content_by_lua_block {
        ngx.print("ok")
    }
}

location = /v {
    set_real_ip_from 127.0.0.1;
    real_ip_header   X-Forwarded-For;
    real_ip_recursive on;
    content_by_lua_block {
        ngx.print("ok")
    }
}

location = /w {
    set $crowdsec_ban_template ./t/vhosts_t/../vhosts_t/ban_a.html;
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
--- response_body_like: VHOST-A BAN PAGE
--- grep_error_log eval
qr/refusing per-vhost template override '[^']+': paths containing '\.\.' are not served/
# Once, from the init block's /w request. The '..' path names a file that exists,
# so anything but a refusal would have served VHOST-A BAN PAGE there.
--- grep_error_log_out
refusing per-vhost template override './t/vhosts_t/../vhosts_t/ban_a.html': paths containing '..' are not served



=== TEST 28b: per-vhost captcha page, compiled per serve, broken page degrades to stock

--- init

use LWP::UserAgent;

my $ua = LWP::UserAgent->new(timeout => 10);

open my $out_fh, '>', 't/servroot/logs/perl.init.log' or die $!;

sub fail {
    print $out_fh "$_[0]\n";
    exit 1;
}

sub captcha_body {
    my ($path) = @_;
    my $req = HTTP::Request->new(GET => "http://127.0.0.1:1984$path");
    $req->header('X-Forwarded-For' => '2.2.2.2');
    # the secure-context gate would divert a plain-HTTP request to the insecure
    # page; this block is about the captcha itself, so declare upstream TLS
    $req->header('X-Forwarded-Proto' => 'https');
    my $resp = $ua->request($req);
    fail("$path: expected the captcha page, got HTTP " . $resp->code)
        unless $resp->code == 200;
    return $resp->decoded_content;
}

# the vhost's own page, compiled: real widget markup and a real inline challenge
my $page = captcha_body('/t');
fail("/t was not served the vhost override") unless $page =~ /VHOST-A CAPTCHA PAGE/;
fail("/t override carries no altcha widget") unless $page =~ /<altcha-widget/;
fail("/t override carries no inline challenge") unless $page =~ m{challenge='(\{[^']*\})'};
fail("/t override still contains unsubstituted placeholders") if $page =~ /\{\{/;
fail("/t override leaked the challenge placeholder") if $page =~ /__CROWDSEC_ALTCHA_CHALLENGE__/;

# a page with no widget slot cannot be served as a captcha - the visitor could
# never solve it - so it degrades to the stock page, and the log says so
my $broken = captcha_body('/u');
fail("/u served the broken override") if $broken =~ /BROKEN VHOST CAPTCHA PAGE/;
fail("/u did not fall back to the stock captcha page")
    unless $broken =~ /<title>CrowdSec Captcha<\/title>/i;

# no override set at all
fail("/v did not serve the stock captcha page")
    unless captcha_body('/v') =~ /<title>CrowdSec Captcha<\/title>/i;

print $out_fh "Override compiled, broken page refused, stock fallbacks served.\n";
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
        local ok, err = cs.init("./t/conf_t/28_per_vhost_templates_crowdsec_nginx_bouncer.conf", "crowdsec-nginx-bouncer/v1.0.8")
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
            if args.ip == "2.2.2.2" then
               ngx.say('[{"duration":"1h00m00s","id":4091593,"origin":"CAPI","scenario":"crowdsecurity/vpatch-CVE-2024-4577","scope":"Ip","type":"captcha","value":"2.2.2.2"}]')
            else
               ngx.print('null')
            end
            }
      }
}

--- config

location = /t {
    set $crowdsec_captcha_template ./t/vhosts_t/captcha_a.html;
    set_real_ip_from 127.0.0.1;
    real_ip_header   X-Forwarded-For;
    real_ip_recursive on;
    content_by_lua_block {
        ngx.print("ok")
    }
}

location = /u {
    set $crowdsec_captcha_template ./t/vhosts_t/captcha_broken.html;
    set_real_ip_from 127.0.0.1;
    real_ip_header   X-Forwarded-For;
    real_ip_recursive on;
    content_by_lua_block {
        ngx.print("ok")
    }
}

location = /v {
    set_real_ip_from 127.0.0.1;
    real_ip_header   X-Forwarded-For;
    real_ip_recursive on;
    content_by_lua_block {
        ngx.print("ok")
    }
}

--- more_headers
X-Forwarded-For: 2.2.2.2
X-Forwarded-Proto: https

--- request
GET /t

--- error_code: 200
--- response_body_like: VHOST-A CAPTCHA PAGE
--- grep_error_log eval
qr/per-vhost captcha template for '[^']+' renders no altcha widget, add \{\{captcha_widget\}\} to it, serving the stock captcha page instead/
# Once, from the init block's /u request; the healthy override and the stock
# fallbacks must not add one.
--- grep_error_log_out eval
qr/per-vhost captcha template for '[^']+' renders no altcha widget, add \{\{captcha_widget\}\} to it, serving the stock captcha page instead/



=== TEST 28c: per-vhost insecure-context page

The plain-HTTP divert page can be overridden the same way. A non-loopback Host is
what makes the request insecure in the first place (loopback is a secure context),
so these requests spell their Host out.

--- init

use LWP::UserAgent;

my $ua = LWP::UserAgent->new(timeout => 10);

open my $out_fh, '>', 't/servroot/logs/perl.init.log' or die $!;

sub fail {
    print $out_fh "$_[0]\n";
    exit 1;
}

sub insecure_body {
    my ($path) = @_;
    my $req = HTTP::Request->new(GET => "http://127.0.0.1:1984$path");
    $req->header(Host => 'vhost-a.test');
    $req->header('X-Forwarded-For' => '2.2.2.2');
    my $resp = $ua->request($req);
    fail("$path: expected the insecure-context 403, got HTTP " . $resp->code)
        unless $resp->code == 403;
    return $resp->decoded_content;
}

fail("/t was not served the vhost override")
    unless insecure_body('/t') =~ /VHOST-A INSECURE PAGE/;

my $global = insecure_body('/v');
fail("/v served the vhost override") if $global =~ /VHOST-A INSECURE PAGE/;
fail("/v did not fall back to the global insecure page")
    unless $global =~ /Verification required/;

print $out_fh "Insecure-context override and fallback both served.\n";
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
        local ok, err = cs.init("./t/conf_t/28_per_vhost_templates_crowdsec_nginx_bouncer.conf", "crowdsec-nginx-bouncer/v1.0.8")
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
            if args.ip == "2.2.2.2" then
               ngx.say('[{"duration":"1h00m00s","id":4091593,"origin":"CAPI","scenario":"crowdsecurity/vpatch-CVE-2024-4577","scope":"Ip","type":"captcha","value":"2.2.2.2"}]')
            else
               ngx.print('null')
            end
            }
      }
}

--- config

location = /t {
    set $crowdsec_captcha_insecure_template ./t/vhosts_t/insecure_a.html;
    set_real_ip_from 127.0.0.1;
    real_ip_header   X-Forwarded-For;
    real_ip_recursive on;
    content_by_lua_block {
        ngx.print("ok")
    }
}

location = /v {
    set_real_ip_from 127.0.0.1;
    real_ip_header   X-Forwarded-For;
    real_ip_recursive on;
    content_by_lua_block {
        ngx.print("ok")
    }
}

--- raw_request eval
"GET /t HTTP/1.1\r
Host: vhost-a.test\r
X-Forwarded-For: 2.2.2.2\r
Connection: close\r
\r
"

--- error_code: 403
--- response_body_like: VHOST-A INSECURE PAGE
--- error_log
cannot run over plain HTTP, serving the insecure-context page instead

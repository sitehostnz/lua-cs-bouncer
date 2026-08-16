# Live mode, CAPTCHA_PROVIDER=altcha, requests arriving over plain HTTP.
#
# The altcha widget derives keys with crypto.subtle, which browsers expose only in
# secure contexts, so a captcha page served to a plain-http:// origin is a dead end:
# the widget throws before doing any work and the visitor has no route through.
# captcha.apply() therefore gates on the visitor's context before serving anything:
#
#   plain HTTP, page configured    -> CAPTCHA_INSECURE_TEMPLATE_PATH, with a ban's
#                                     status, and without minting a challenge
#   plain HTTP, page not set       -> the ban remediation
#   X-Forwarded-Proto: https       -> the captcha (TLS terminated upstream)
#   loopback / localhost origin    -> the captcha (a secure context whatever the
#                                     scheme, which is what keeps local development
#                                     and this suite's own 127.0.0.1 requests working)
#
# Every request this suite makes is plain HTTP, so "secure" is asserted through the
# forwarded header and the loopback Host, and "insecure" needs a Host that is not
# loopback - LWP and raw_request supply one, since Test::Nginx's default is localhost.

use Test::Nginx::Socket 'no_plan';

run_tests();

__DATA__

=== TEST 27: a plain-HTTP captcha decision is served the insecure-context page

--- init

use LWP::UserAgent;

my $ua = LWP::UserAgent->new(timeout => 10);
my $url = 'http://127.0.0.1:1984/t';

open my $out_fh, '>', 't/servroot/logs/perl.init.log' or die $!;

sub fail {
    print $out_fh "$_[0]\n";
    exit 1;
}

sub probe {
    my ($key) = @_;
    my $r = $ua->get("http://127.0.0.1:1984/_dict?key=$key");
    fail("could not read the altcha dict: HTTP " . $r->code) unless $r->is_success;
    return $r->decoded_content;
}

# --- plain HTTP on a real (non-loopback) host: the page, not the widget ---------
my $req = HTTP::Request->new(GET => $url);
$req->header(Host => 'plainhttp.example');
$req->header('X-Forwarded-For' => '1.1.1.1');
my $resp = $ua->request($req);

fail("expected the insecure-context page with a ban's 403, got HTTP " . $resp->code)
    unless $resp->code == 403;
fail("the insecure-context page was not served")
    unless $resp->decoded_content =~ /Verification required/;
fail("a plain-HTTP request was served the captcha widget")
    if $resp->decoded_content =~ /<altcha-widget/;

# The gate has to run before the challenge is minted: a challenge the visitor can
# never see must not be derived (that is nginx CPU) nor charged against the mint
# budget (eleven of these would turn an honest visitor's next captcha into a ban).
for my $key (qw(altcha_challenge_1.1.1.1 altcha_mints_1.1.1.1)) {
    my $got = probe($key);
    fail("$key exists after a request that never saw a captcha: $got")
        unless $got =~ /^absent/;
}

# --- same host, TLS terminated upstream: the widget ------------------------------
$req = HTTP::Request->new(GET => $url);
$req->header(Host => 'plainhttp.example');
$req->header('X-Forwarded-For' => '1.1.1.1');
$req->header('X-Forwarded-Proto' => 'https');
$resp = $ua->request($req);

fail("X-Forwarded-Proto: https was not honoured, got HTTP " . $resp->code)
    unless $resp->code == 200;
fail("expected the captcha widget behind an upstream TLS terminator")
    unless $resp->decoded_content =~ /<altcha-widget/;

# the positive control for the probes above: minting resumes once the context is
# secure, so their earlier absence meant "gated", not "broken counters"
fail("no challenge outstanding after the widget was served")
    unless probe('altcha_challenge_1.1.1.1') =~ /^present/;

# --- loopback origin over plain HTTP: still the widget ---------------------------
# LWP sends Host: 127.0.0.1:1984 here, and loopback is a secure context whatever
# the scheme - this is local development, and incidentally every other test file.
$req = HTTP::Request->new(GET => $url);
$req->header('X-Forwarded-For' => '1.1.1.1');
$resp = $ua->request($req);

fail("a loopback origin was refused the captcha, got HTTP " . $resp->code)
    unless $resp->code == 200;
fail("expected the captcha widget on a loopback origin")
    unless $resp->decoded_content =~ /<altcha-widget/;

print $out_fh "Gated on plainhttp.example, served via XFP and loopback.\n";
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
        local ok, err = cs.init("./t/conf_t/27_live_captcha_insecure_crowdsec_nginx_bouncer.conf", "crowdsec-nginx-bouncer/v1.0.8")
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

# Test-only white-box read of the altcha dict, as in t/25. Probed without an
# X-Forwarded-For, so it arrives as 127.0.0.1 and the LAPI stub declines to bounce it.
location = /_dict {
    content_by_lua_block {
        local key = ngx.req.get_uri_args()["key"]
        local v = ngx.shared.crowdsec_altcha:get(key)
        ngx.print(v == nil and "absent" or ("present:" .. tostring(v)))
    }
}

# Test::Nginx's own request cannot change its Host header (more_headers would just
# duplicate it), so the non-loopback request is spelt out in full.
--- raw_request eval
"GET /t HTTP/1.1\r
Host: plainhttp.example\r
X-Forwarded-For: 1.1.1.1\r
Connection: close\r
\r
"

--- error_code: 403
--- response_body_like: Verification required
--- error_log
[Crowdsec] denied '1.1.1.1' with 'captcha'
--- grep_error_log eval
qr/captcha for '1\.1\.1\.1' cannot run over plain HTTP, serving the insecure-context page instead/
# Twice: the init block's first request and the raw request above. The XFP and
# loopback requests must not add one - that they are missing here is the assertion
# that neither was gated.
--- grep_error_log_out
captcha for '1.1.1.1' cannot run over plain HTTP, serving the insecure-context page instead
captcha for '1.1.1.1' cannot run over plain HTTP, serving the insecure-context page instead
--- no_error_log
serving a ban instead



=== TEST 27b: without the page configured, plain HTTP degrades to the ban remediation

CAPTCHA_INSECURE_TEMPLATE_PATH is unset, so the same request is handed to ban.apply()
instead - here a bare 403, since the fixture sets no ban template either. The decision
stays 'captcha' (the denial log pins that); only the serving degrades.

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
        local ok, err = cs.init("./t/conf_t/27b_no_insecure_template_crowdsec_nginx_bouncer.conf", "crowdsec-nginx-bouncer/v1.0.8")
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

--- raw_request eval
"GET /t HTTP/1.1\r
Host: plainhttp.example\r
X-Forwarded-For: 1.1.1.1\r
Connection: close\r
\r
"

--- error_code: 403
--- response_body_unlike: Verification required
--- error_log eval
[
"[Crowdsec] denied '1.1.1.1' with 'captcha'",
"captcha for '1.1.1.1' cannot run over plain HTTP and no insecure-context page is configured, serving a ban instead",
]



=== TEST 27c: an unreadable page path is reported at startup and behaves as unset

The operator asked for a page the bouncer cannot read. That must be loud at init and
degrade to the ban remediation per request - not take the captcha provider down with
it, which would cost the HTTPS visitors their captcha too.

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
        local ok, err = cs.init("./t/conf_t/27c_unreadable_insecure_template_crowdsec_nginx_bouncer.conf", "crowdsec-nginx-bouncer/v1.0.8")
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

--- raw_request eval
"GET /t HTTP/1.1\r
Host: plainhttp.example\r
X-Forwarded-For: 1.1.1.1\r
Connection: close\r
\r
"

--- error_code: 403
--- error_log eval
[
"CAPTCHA_INSECURE_TEMPLATE_PATH './no-such-page.html' cannot be read, captcha decisions over plain HTTP will be served a ban instead",
"captcha for '1.1.1.1' cannot run over plain HTTP and no insecure-context page is configured, serving a ban instead",
]

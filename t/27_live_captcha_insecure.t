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
#   $crowdsec_assume_secure 1      -> the captcha (TLS terminated upstream, declared
#                                     by the operator rather than guessed at)
#   loopback / localhost origin    -> the captcha (a secure context whatever the
#                                     scheme, which is what keeps local development
#                                     and this suite's own 127.0.0.1 requests working)
#   X-Forwarded-Proto: https       -> NOT honoured, deliberately. Nothing can tell a
#                                     header the trusted proxy set from one the client
#                                     sent and the proxy passed through, so the gate
#                                     does not consult it at all. The last case below
#                                     is the regression test for that.
#
# Every request this suite makes is plain HTTP, so "secure" is asserted through the
# operator switch and the loopback Host, and "insecure" needs a Host that is not
# loopback - LWP and raw_request supply one, since Test::Nginx's default is localhost.

use Test::Nginx::Socket 'no_plan';

run_tests();

__DATA__

=== TEST 27: a plain-HTTP captcha decision is served the insecure-context page

--- init

use LWP::UserAgent;

my $ua = LWP::UserAgent->new(timeout => 10);
my $url = 'http://127.0.0.1:1984/t';

# die, not print-to-a-file-then-exit: Test::Nginx wraps --- init in an eval and turns a
# die into a reported block failure carrying the message. The old form put the reason in
# t/servroot/logs/ (truncated next run, root-owned in the container) and exited, which
# abandoned 27b and 27c as well. This file's most security-relevant assertion - that a
# client-supplied X-Forwarded-Proto is NOT honoured - reports through here.
sub fail {
    die "TEST 27: $_[0]\n";
}

sub probe {
    my ($key) = @_;
    my $r = $ua->get("http://127.0.0.1:1984/_dict?key=$key");
    fail("could not read the altcha dict: HTTP " . $r->code) unless $r->is_success;
    return $r->decoded_content;
}

sub cache_probe {
    my ($key) = @_;
    my $r = $ua->get("http://127.0.0.1:1984/_cache?key=$key");
    fail("could not read crowdsec_cache: HTTP " . $r->code) unless $r->is_success;
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

# The gate has to run before the VERIFY_STATE entry is written, not after. crowdsec_cache
# is the same shared dict that holds the decision cache, so one entry per bounced address
# for a captcha that was refused is an attacker-paced write competing with the decisions
# the bouncer exists to enforce - and once it exists, every later request from that
# address reads its body and runs validateCaptcha() to conclude there is nothing to
# validate, logging "Invalid captcha from" for a visitor who was never offered one.
#
# Same shape as the two altcha_* probes below, which prove the mint budget is not charged.
fail("a refused captcha still wrote a verify entry: " . cache_probe('captcha_1.1.1.1'))
    unless cache_probe('captcha_1.1.1.1') =~ /^absent/;

# The gate has to run before the challenge is minted: a challenge the visitor can
# never see must not be derived (that is nginx CPU) nor charged against the mint
# budget (eleven of these would turn an honest visitor's next captcha into a ban).
for my $key (qw(altcha_challenge_1.1.1.1 altcha_mints_1.1.1.1)) {
    my $got = probe($key);
    fail("$key exists after a request that never saw a captcha: $got")
        unless $got =~ /^absent/;
}

# --- X-Forwarded-Proto is NOT consulted -----------------------------------------
# The regression test for removing that branch. A client can send this header, and
# nothing here can distinguish it from one a trusted proxy set, so honouring it would
# let any visitor on a plaintext vhost choose a scriptable challenge over a denial.
$req = HTTP::Request->new(GET => $url);
$req->header(Host => 'plainhttp.example');
$req->header('X-Forwarded-For' => '1.1.1.1');
$req->header('X-Forwarded-Proto' => 'https');
$resp = $ua->request($req);

fail("X-Forwarded-Proto was honoured, got HTTP " . $resp->code . " - the gate must ignore it")
    unless $resp->code == 403;
fail("a client-supplied X-Forwarded-Proto was served the captcha widget")
    if $resp->decoded_content =~ /<altcha-widget/;

# The hint that names $crowdsec_assume_secure is at ERR, and this header's shape is
# exactly the misconfiguration it diagnoses - so a flood of them would be a flood of
# ERR lines. It is latched per worker. Two more requests, then the count has to be one.
for (1 .. 2) {
    my $again = HTTP::Request->new(GET => $url);
    $again->header(Host => 'plainhttp.example');
    $again->header('X-Forwarded-For' => '1.1.1.1');
    $again->header('X-Forwarded-Proto' => 'https');
    $ua->request($again);
}
my $hints = $ua->get('http://127.0.0.1:1984/_hintcount');
fail("could not count the upgrade hint: HTTP " . $hints->code) unless $hints->is_success;
fail("three X-Forwarded-Proto requests logged the upgrade hint "
    . $hints->decoded_content . " times, expected 1 - the per-worker latch is not held")
    unless $hints->decoded_content eq '1';

# --- same host, TLS terminated upstream, declared by the operator: the widget -----
# $crowdsec_assume_secure is the documented replacement for the header above, and
# this is its only coverage anywhere in the suite.
$req = HTTP::Request->new(GET => 'http://127.0.0.1:1984/assume');
$req->header(Host => 'plainhttp.example');
$req->header('X-Forwarded-For' => '1.1.1.1');
$resp = $ua->request($req);

fail("\$crowdsec_assume_secure was not honoured, got HTTP " . $resp->code)
    unless $resp->code == 200;
fail("expected the captcha widget where the operator asserted a secure context")
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

# Counts the upgrade diagnostic in the error log. The --- error_log section below only
# proves the line appears; the hint is meant to fire once per worker, and presence alone
# cannot tell that from once per request.
location = /_hintcount {
    content_by_lua_block {
        local fh = io.open(ngx.config.prefix() .. "logs/error.log", "r")
        if fh == nil then ngx.print("nolog") return end
        local n = 0
        for line in fh:lines() do
            if line:find("crowdsec_assume_secure 1", 1, true) ~= nil then n = n + 1 end
        end
        fh:close()
        ngx.print(n)
    }
}

# Same as /t, plus the operator's assertion that this vhost is reached over HTTPS.
# The only place in the suite where $crowdsec_assume_secure is set at all.
location = /assume {
    set $crowdsec_assume_secure 1;
    set_real_ip_from 127.0.0.1;
    real_ip_header   X-Forwarded-For;
    real_ip_recursive on;
    content_by_lua_block {
        ngx.print("PROTECTED")
    }
}

# Test-only white-box read of the altcha dict, as in t/25. Probed without an
# X-Forwarded-For, so it arrives as 127.0.0.1 and the LAPI stub declines to bounce it.
location = /_cache {
    content_by_lua_block {
        local key = ngx.req.get_uri_args()["key"]
        local v = ngx.shared.crowdsec_cache:get(key)
        ngx.print(v == nil and "absent" or ("present:" .. tostring(v)))
    }
}

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
--- error_log eval
[
"[Crowdsec] denied '1.1.1.1' with 'captcha'",
# The upgrade diagnostic. The two per-request lines about plain HTTP are at INFO, below
# nginx's default error_log level, so on a real deployment neither is visible; this one
# is at ERR and names the fix. Emitted once per worker, from the init block's
# X-Forwarded-Proto request.
"add `set \$crowdsec_assume_secure 1;`",
]
--- grep_error_log eval
qr/captcha for '1\.1\.1\.1' cannot run over plain HTTP, serving the insecure-context page instead/
# Five times: the init block's first request, its three X-Forwarded-Proto requests, and
# the raw request above. The XFP ones being counted here are the assertion that the
# header is no longer consulted; the loopback and $crowdsec_assume_secure requests must
# NOT add one, and their absence is the assertion that both still pass the gate.
--- grep_error_log_out
captcha for '1.1.1.1' cannot run over plain HTTP, serving the insecure-context page instead
captcha for '1.1.1.1' cannot run over plain HTTP, serving the insecure-context page instead
captcha for '1.1.1.1' cannot run over plain HTTP, serving the insecure-context page instead
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

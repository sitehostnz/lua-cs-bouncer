# Live mode, CAPTCHA_PROVIDER=altcha.
#   --- init      GETs on /t      -> the altcha widget, carrying a challenge that is
#                                    reused across reloads of one IP and differs
#                                    between IPs, plus the verify state
#                 POST /t         -> a wrong answer is refused and, importantly,
#                                    leaves the outstanding challenge alone
#   --- request   POST /t         -> a second wrong answer is refused and the captcha
#                                    is served again
#
# There is no stub server here, and that is the point: altcha mints and checks its
# own challenges, so nothing in this test stands in for a third party.
#
# Solving the proof of work would mean running PBKDF2 a few thousand times, which
# is not something to ask of a Perl test block. The round trip through a genuine
# solution is covered outside this suite.

use Test::Nginx::Socket 'no_plan';

run_tests();

__DATA__

=== TEST 23: Live mode altcha captcha

--- init

use LWP::UserAgent;

my $ua = LWP::UserAgent->new;
my $url = 'http://127.0.0.1:1984/t';

open my $out_fh, '>', 't/servroot/logs/perl.init.log' or die $!;
print $out_fh "Starting initialization...\n";

sub fetch_captcha_page {
    my ($ip) = @_;
    my $req = HTTP::Request->new(GET => $url);
    $req->header('X-Forwarded-For' => $ip);
    my $resp = $ua->request($req);
    if (!$resp->is_success || $resp->code != 200) {
        print $out_fh "Expected the captcha page, got HTTP " . $resp->code . "\n";
        exit 1;
    }
    return $resp->decoded_content;
}

sub challenge_of {
    my ($page) = @_;
    if ($page !~ m{challenge='(\{[^']*\})'}) {
        print $out_fh "no inline challenge on the widget\n";
        exit 1;
    }
    return $1;
}

my $content = fetch_captcha_page('1.1.1.1');

if ($content !~ /<title>CrowdSec Captcha<\/title>/i) {
    print $out_fh "Captcha template was not served\n";
    exit 1;
}

# the widget must name its hidden input to match GetCaptchaBackendKey(), and must
# carry auto="onload": solving starts as the page paints, so the visitor's whole
# CAPTCHA_VERIFY_TTL verify window is spent on the work rather than on noticing a button
if ($content !~ m{<altcha-widget id="captcha" name="altcha-response"}) {
    print $out_fh "altcha-widget missing, or not renaming its hidden field\n";
    exit 1;
}
if ($content !~ m{<altcha-widget[^>]*\bauto="onload"}) {
    print $out_fh "altcha-widget is not set to solve on load\n";
    exit 1;
}

# the widget is an ES module, a plain script tag would never define the element
if ($content !~ m{<script async defer type="module" src="https://cdn\.jsdelivr\.net/npm/altcha\@}) {
    print $out_fh "widget script tag is missing type=module\n";
    exit 1;
}

# the challenge is inline rather than fetched, so it has to be complete here:
# altcha's widget rejects one missing any of algorithm/nonce/salt/keyPrefix
my $challenge = challenge_of($content);

for my $field (qw(algorithm nonce salt keyPrefix cost keyLength expiresAt)) {
    if ($challenge !~ /"\Q$field\E":/) {
        print $out_fh "challenge is missing $field: $challenge\n";
        exit 1;
    }
}

# m{} rather than //, and the slash optionally escaped: cjson escapes forward
# slashes on the way out, so this arrives as PBKDF2\/SHA-256. That is a legal JSON
# escape and the widget's JSON.parse undoes it, so only the assertion cares.
if ($challenge !~ m{"algorithm":"PBKDF2\\?/SHA-256"}) {
    print $out_fh "challenge does not advertise PBKDF2/SHA-256: $challenge\n";
    exit 1;
}

# 16 random bytes each, hex encoded, and half of a 32 byte key as the prefix
if ($challenge !~ /"nonce":"([0-9a-f]{32})"/) {
    print $out_fh "nonce is not 16 hex-encoded bytes: $challenge\n";
    exit 1;
}
my $first_nonce = $1;

if ($challenge !~ /"salt":"[0-9a-f]{32}"/ || $challenge !~ /"keyPrefix":"[0-9a-f]{32}"/) {
    print $out_fh "salt or keyPrefix is not 16 hex-encoded bytes: $challenge\n";
    exit 1;
}

if ($challenge !~ /"cost":100\b/) {
    print $out_fh "challenge did not pick up ALTCHA_COST: $challenge\n";
    exit 1;
}

# Reloading must hand back the challenge already outstanding for this IP rather
# than deriving another: that is what stops a bounced visitor turning reloads into
# unbounded work for nginx.
if (challenge_of(fetch_captcha_page('1.1.1.1')) ne $challenge) {
    print $out_fh "a reload derived a second challenge for the same IP\n";
    exit 1;
}

# A different visitor must not be handed the first one.
my $other = challenge_of(fetch_captcha_page('2.2.2.2'));
if ($other !~ m{"nonce":"([0-9a-f]{32})"} || $1 eq $first_nonce) {
    print $out_fh "another IP was served the same challenge\n";
    exit 1;
}

# A wrong answer must leave the challenge alone. Redeeming it here instead would let
# anyone clear the entry with a payload costing nothing to produce, so the next page
# load pays for a fresh derivation - and with a mint ceiling in front of that, enough
# junk POSTs stop being served a captcha at all and start being banned. Since one
# challenge is shared by everyone behind a NAT, that is a lockout anybody on the
# address can inflict on their neighbours.
#
# Asserted on the nonce rather than the response, because the visible behaviour is
# identical either way: both serve the captcha page again.
my $junk = HTTP::Request->new(POST => $url);
$junk->header('X-Forwarded-For' => '1.1.1.1');
$junk->header('Content-Type' => 'application/x-www-form-urlencoded');
# {"challenge":{"parameters":{}},"solution":{"counter":1,"derivedKey":"deadbeef","time":1}}
$junk->content('altcha-response=eyJjaGFsbGVuZ2UiOnsicGFyYW1ldGVycyI6e319LCJzb2x1dGlvbiI6eyJjb3VudGVyIjoxLCJkZXJpdmVkS2V5IjoiZGVhZGJlZWYiLCJ0aW1lIjoxfX0%3D');
$ua->request($junk);

if (challenge_of(fetch_captcha_page('1.1.1.1')) ne $challenge) {
    print $out_fh "a wrong answer destroyed the outstanding challenge\n";
    exit 1;
}

# The captcha field does not have to arrive as a string. ngx.req.get_post_args()
# yields the boolean true for a field submitted with no '=', and a table for one
# submitted twice - and both are non-nil, so both reach Validate(). Everything past
# that point assumes a string: ngx.decode_base64() raises on anything else, and the
# other providers concatenate it into a form body. Unguarded, either of these is an
# uncaught error in the access phase, which means a 500 and a Lua traceback in the
# log for anyone who can be served a captcha page.
#
# Both must come back as an ordinary refused captcha - the page again, not a 500.
for my $body ('altcha-response', 'altcha-response=a&altcha-response=b') {
    my $malformed = HTTP::Request->new(POST => $url);
    $malformed->header('X-Forwarded-For' => '1.1.1.1');
    $malformed->header('Content-Type' => 'application/x-www-form-urlencoded');
    $malformed->content($body);
    my $resp = $ua->request($malformed);
    if ($resp->code != 200) {
        print $out_fh "a malformed captcha field ('$body') gave HTTP "
            . $resp->code . " rather than the captcha page\n";
        exit 1;
    }
}

if ($content =~ /\{\{/) {
    print $out_fh "template still contains unsubstituted placeholders\n";
    exit 1;
}

print $out_fh "Captcha page served as expected.\n";
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
        local ok, err = cs.init("./t/conf_t/23_live_captcha_altcha_crowdsec_nginx_bouncer.conf", "crowdsec-nginx-bouncer/v1.0.8")
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
            -- both IPs need a decision: the test compares the challenge issued to
            -- one against the challenge issued to the other, so both have to be
            -- bounced far enough to be served a captcha page at all
            if args.ip == "1.1.1.1" or args.ip == "2.2.2.2" then
               ngx.say('[{"duration":"1h00m00s","id":4091593,"origin":"CAPI","scenario":"crowdsecurity/vpatch-CVE-2024-4577","scope":"Ip","type":"captcha","value":"' .. args.ip .. '"}]')
            else
               -- 'null', not '[{}]': an empty decision object reaches live.lua as a
               -- table with no fields and blows up concatenating decision.origin
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
Content-Type: application/x-www-form-urlencoded

# a well-formed payload whose derived key is not the one outstanding for this IP:
# right length, wrong value, so it must not be taken as a solution. The lookup does
# not miss - 1.1.1.1 still has a live challenge, because the init block's junk POST
# left it alone - so this exercises the comparison rather than the not-found path.
--- request eval
"POST /t
altcha-response=eyJjaGFsbGVuZ2UiOnsicGFyYW1ldGVycyI6eyJhbGdvcml0aG0iOiJQQktERjIvU0hBLTI1NiIsIm5vbmNlIjoiMDAxMTIyMzM0NDU1NjY3Nzg4OTlhYWJiY2NkZGVlZmYiLCJzYWx0IjoiZmZlZWRkY2NiYmFhOTk4ODc3NjY1NTQ0MzMyMjExMDAiLCJjb3N0IjoxMDAsImtleUxlbmd0aCI6MzIsImtleVByZWZpeCI6IjAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwIn19LCJzb2x1dGlvbiI6eyJjb3VudGVyIjoxLCJkZXJpdmVkS2V5IjoiMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMCIsInRpbWUiOjEyfX0%3D"

--- error_code: 200
--- response_body_like: <altcha-widget
--- grep_error_log eval
qr/Invalid captcha from [0-9.]+/
# Four, all from 1.1.1.1. The init block submits three: a junk payload to prove a
# wrong answer leaves the challenge alone, then a valueless field and a repeated one
# to prove a non-string captcha field is refused rather than raising. The request
# below submits the fourth. That the last two appear here at all is the assertion -
# an unguarded Validate() would have raised on them and logged a traceback instead.
--- grep_error_log_out
Invalid captcha from 1.1.1.1
Invalid captcha from 1.1.1.1
Invalid captcha from 1.1.1.1
Invalid captcha from 1.1.1.1



=== TEST 23b: altcha refuses to configure without its shared dict

No crowdsec_altcha dict in this block's http config. captcha.New() has to fail at
init - challenges are attacker-paced writes, and the old fallback let them share
crowdsec_cache with the decision cache they could then evict - leaving captcha
unusable, so the captcha decision for 1.1.1.1 degrades to FALLBACK_REMEDIATION
instead of silently writing challenges next to the decisions.

--- main_config
load_module /usr/share/nginx/modules/ndk_http_module.so;
load_module /usr/share/nginx/modules/ngx_http_lua_module.so;

--- http_config

lua_package_path './lib/?.lua;;';
lua_shared_dict crowdsec_cache 50m;
lua_ssl_trusted_certificate /etc/ssl/certs/ca-certificates.crt;

init_by_lua_block
{
        cs = require "crowdsec"
        local ok, err = cs.init("./t/conf_t/23_live_captcha_altcha_crowdsec_nginx_bouncer.conf", "crowdsec-nginx-bouncer/v1.0.8")
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
--- error_log eval
[
"error loading captcha plugin: captcha provider 'altcha' needs its own shared dict",
"[Crowdsec] denied '1.1.1.1' with 'ban'",
]



=== TEST 23c: the mint ceiling is reached through churn and degrades to a ban

MAX_MINTS_PER_WINDOW is 10 per CHALLENGE_TTL, and reloads reuse the outstanding
challenge, so the only way to spend the budget is the challenge going away between
requests - eviction under dict pressure in production, a white-box delete here (the
same trick t/25 uses to read the dict, because eviction cannot be provoked on
demand). The eleventh mint has to be refused and served as a ban, not as a page
whose challenge could never be issued.

--- init

use LWP::UserAgent;

my $ua = LWP::UserAgent->new(timeout => 10);
my $url = 'http://127.0.0.1:1984/t';

open my $out_fh, '>', 't/servroot/logs/perl.init.log' or die $!;

sub fail {
    print $out_fh "$_[0]\n";
    exit 1;
}

for my $mint (1 .. 10) {
    my $req = HTTP::Request->new(GET => $url);
    $req->header('X-Forwarded-For' => '1.1.1.1');
    my $resp = $ua->request($req);
    fail("mint $mint: expected the captcha page, got HTTP " . $resp->code)
        unless $resp->code == 200 && $resp->decoded_content =~ /<altcha-widget/;

    # evict the outstanding challenge so the next request has to mint afresh;
    # the mint counter deliberately survives this
    my $scrub = $ua->get('http://127.0.0.1:1984/_scrub');
    fail("mint $mint: could not scrub the challenge: HTTP " . $scrub->code)
        unless $scrub->is_success && $scrub->decoded_content eq 'scrubbed';
}

my $req = HTTP::Request->new(GET => $url);
$req->header('X-Forwarded-For' => '1.1.1.1');
my $resp = $ua->request($req);
fail("11th mint: expected the ban page with 403, got HTTP " . $resp->code)
    unless $resp->code == 403;

print $out_fh "Ten mints served, the eleventh banned.\n";
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
        local ok, err = cs.init("./t/conf_t/23_live_captcha_altcha_crowdsec_nginx_bouncer.conf", "crowdsec-nginx-bouncer/v1.0.8")
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

# Test-only white-box delete, probed without an X-Forwarded-For so it arrives as
# 127.0.0.1 and the LAPI stub declines to bounce it.
location = /_scrub {
    content_by_lua_block {
        ngx.shared.crowdsec_altcha:delete("altcha_challenge_1.1.1.1")
        ngx.print("scrubbed")
    }
}

--- more_headers
X-Forwarded-For: 1.1.1.1

--- request
GET /t

--- error_code: 403
--- error_log eval
[
"altcha mint limit reached for 1.1.1.1 (10 per 1200s)",
"failed to issue an altcha challenge, serving a ban instead",
]


=== TEST 23d: the aggregate mint budget refuses a mint but never a reuse

The per-IP ceiling in 23c is keyed on the address, so a rotating source never reaches
it. The aggregate budget is what bounds the total, and it is expressed in blocking
milliseconds per worker-second rather than in mints, so M.New() calibrates it against
a real derivation on this host. At ALTCHA_COST=100 that lands in the thousands, which
is far too many to spend by minting - so the counter is pre-set instead, keyed on the
wall-clock second exactly as Challenge() keys it.

Two things have to hold here, and the second is the reason the check sits below the
reuse fast path rather than at the top of Challenge():

  1. over budget, with nothing outstanding  -> refused, and served as a ban
  2. over budget, with a challenge already outstanding -> still served the widget,
     because handing back an existing challenge costs no derivation and must never
     be refused for want of budget - otherwise a flood locks out the people who are
     already mid-solve

Expiry is deliberately not asserted here. The counter is pre-set, so what expires is
the TTL this block writes rather than the one Challenge() writes, and an assertion that
cannot fail for the right reason is worse than none. 23e drives the real counter.

The budget is armed for a span of seconds rather than just the current one: a request
that landed a second later than the arming would otherwise find a fresh counter and
pass, which is a race rather than a regression.

--- init

use LWP::UserAgent;

my $ua = LWP::UserAgent->new(timeout => 10);

sub fail_23d { die "TEST 23d: $_[0]\n" }

sub captcha_for {
    my ($ip) = @_;
    my $req = HTTP::Request->new(GET => 'http://127.0.0.1:1984/t');
    $req->header('X-Forwarded-For' => $ip);
    return $ua->request($req);
}

sub probe {
    my ($path) = @_;
    my $resp = $ua->get("http://127.0.0.1:1984$path");
    fail_23d("$path: HTTP " . $resp->code) unless $resp->is_success;
    return $resp->decoded_content;
}

# The calibration itself. A number below 1 would mean New() divided by a cost it
# measured as free; a number this low at ALTCHA_COST=100 would mean it measured the
# clock rather than the KDF, which is exactly the mistake this probe is here to catch.
my $budget = probe('/_budget');
fail_23d("MintsPerSecond is '$budget', expected a number")
    unless $budget =~ /^\d+$/;
fail_23d("MintsPerSecond calibrated to $budget, too low for ALTCHA_COST=100 - the "
    . "probe in New() has most likely measured clock staleness rather than a derivation")
    unless $budget >= 10;

# 1. a mint under budget, which also leaves a challenge outstanding for step 2
my $first = captcha_for('1.1.1.1');
fail_23d("first mint: expected the widget, got HTTP " . $first->code)
    unless $first->code == 200 && $first->decoded_content =~ /<altcha-widget/;

# 2. over budget, but the challenge from step 1 is still outstanding
probe('/_exhaust?span=2');
my $reused = captcha_for('1.1.1.1');
fail_23d("reuse over budget: expected the widget anyway, got HTTP " . $reused->code
    . " - the budget check has moved above the reuse fast path")
    unless $reused->code == 200 && $reused->decoded_content =~ /<altcha-widget/;

# 3. over budget with nothing outstanding: the mint has to be refused
probe('/_scrub');
probe('/_exhaust?span=2');
my $refused = captcha_for('1.1.1.1');
fail_23d("over budget: expected a ban with 403, got HTTP " . $refused->code)
    unless $refused->code == 403;

# The refusal is reported once per worker per second, not once per request. Eight
# refusals inside one second have to yield exactly one report, and the message has to
# carry the running count so a single line still shows the scale.
my $shed = probe('/_shed');
fail_23d("shed pattern was '$shed', expected the first refusal to report and the next "
    . "seven to be suppressed - otherwise the log grows a line per flooded request")
    unless $shed =~ /^false,true,true,true,true,true,true,true /;
fail_23d("shed reported '$shed': a refusal message did not carry its count")
    unless $shed =~ /counted=8/;
fail_23d("shed reported '$shed': a non-budget failure was marked already-reported, "
    . "which would suppress a real fault to save a write")
    unless $shed =~ /nonshed=nil$/;

# And end to end: a burst of refused requests must not produce a line each. Twenty
# requests fit inside a second or two, so a handful of reports is right and twenty is
# the bug. Fired as one address because a refused request never creates a challenge,
# so every one of them re-attempts and is refused again.
probe('/_scrub');
probe('/_exhaust?span=8');
# Into a fresh second first: /_shed has just reported for its own second, and a burst
# landing inside that second is correctly silent - which would make the lower bound
# below fail for the right reason and mean nothing.
sleep 1;
my $before = probe('/_logcount');
captcha_for('1.1.1.1') for 1 .. 20;
my $after = probe('/_logcount');
my $written = $after - $before;
fail_23d("20 refused requests wrote $written log lines - the caller is not acting on "
    . "the already-reported flag, so a flood is also a disk-write flood")
    unless $written >= 1 && $written <= 6;

# Leave the budget exhausted across a wide span, and nothing outstanding, so the
# request below has to mint and has to be refused.
probe('/_scrub');
probe('/_exhaust?span=8');

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
        local ok, err = cs.init("./t/conf_t/23_live_captcha_altcha_crowdsec_nginx_bouncer.conf", "crowdsec-nginx-bouncer/v1.0.8")
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

# The three probes below are reached without an X-Forwarded-For, so they arrive as
# 127.0.0.1 and the LAPI stub declines to bounce them.

location = /_budget {
    content_by_lua_block {
        ngx.print(require("plugins.crowdsec.altcha").MintsPerSecond)
    }
}

# Pre-set the aggregate counter above the calibrated cap for `span` consecutive
# seconds, keyed the way Challenge() keys it. incr() only applies its init_ttl when
# it creates the key, so the TTL set here is what governs expiry - which is what
# step 4 above relies on.
location = /_exhaust {
    content_by_lua_block {
        local altcha = require "plugins.crowdsec.altcha"
        local span = tonumber(ngx.req.get_uri_args().span) or 2
        local over = altcha.MintsPerSecond + 1
        local now = ngx.time()
        for offset = 0, span - 1 do
            ngx.shared.crowdsec_altcha:set("altcha_mint_budget_" .. (now + offset), over, span + 2)
        end
        ngx.print("exhausted ", span, "s at ", over)
    }
}

location = /_scrub {
    content_by_lua_block {
        ngx.shared.crowdsec_altcha:delete("altcha_challenge_1.1.1.1")
        ngx.print("scrubbed")
    }
}

# Exercises the refusal's third return value - "already reported this second" - which is
# what stops the caller writing one ERR line per refused request. Everything happens in
# one request so the wall-clock second cannot move underneath it, and it waits for a
# fresh second first so the per-worker latch is guaranteed unset when it starts.
# Counts what actually landed in the error log. The /_shed probe above proves the
# refusal reports itself once per second; this proves the caller acts on that, which is
# the half that decides the log volume.
location = /_logcount {
    content_by_lua_block {
        local fh = io.open(ngx.config.prefix() .. "logs/error.log", "r")
        if fh == nil then ngx.print("nolog") return end
        local n = 0
        for line in fh:lines() do
            if line:find("failed to issue an altcha challenge", 1, true) ~= nil then
                n = n + 1
            end
        end
        fh:close()
        ngx.print(n)
    }
}

location = /_shed {
    content_by_lua_block {
        local altcha = require "plugins.crowdsec.altcha"
        local s = ngx.shared.crowdsec_altcha

        local waited = ngx.time()
        while ngx.time() == waited do ngx.sleep(0.01) end

        local now = ngx.time()
        s:set("altcha_mint_budget_" .. now, altcha.MintsPerSecond + 1, 10)

        local flags, counted = {}, 0
        for i = 1, 8 do
            local challenge, err, reported = altcha.Challenge("203.0.113." .. i)
            if challenge ~= nil then
                flags[#flags + 1] = "SERVED"
            else
                flags[#flags + 1] = tostring(reported)
                if err:find("refused this second", 1, true) ~= nil then
                    counted = counted + 1
                end
            end
        end

        -- a failure that is not load shedding must never be suppressed
        local _, _, nonshed = altcha.Challenge("")
        ngx.print(table.concat(flags, ","), " counted=", counted,
            " nonshed=", tostring(nonshed))
    }
}

--- more_headers
X-Forwarded-For: 1.1.1.1

--- request
GET /t

--- error_code: 403
--- error_log eval
[
"altcha mint budget exhausted",
"failed to issue an altcha challenge, serving a ban instead",
]
--- no_error_log
altcha mint limit reached for 1.1.1.1


=== TEST 23e: rotating addresses reach the aggregate budget that the per-IP ceiling misses

23c reaches the per-IP ceiling by minting eleven times as one address. That is the
limit an attacker never meets: a fresh address carries a fresh counter, so ten mints
each from a thousand addresses spends ten thousand derivations and trips nothing. This
block is that attack, and the assertion is that the aggregate budget stops it while the
per-IP ceiling stays untouched - every address here mints exactly once, so if the
per-IP message appears at all, the wrong limit fired.

ALTCHA_COST is at MAX_COST so a derivation is expensive enough for the calibrated
budget to be reachable by minting for real, rather than by pre-setting the counter as
23d has to. That is what makes this the block that can assert expiry: the 2s init_ttl
under test is the one Challenge() writes.

The budget is spent by definition in ~50 ms of derivation per worker-second, so the
loop below costs about that regardless of how fast the host is - a faster host raises
the cap and each mint gets correspondingly cheaper. The bound is derived from the
probed cap rather than hardcoded for the same reason. Firing more than the cap does
not guarantee a refusal on the first pass, because the mints can straddle a second
boundary and land either side of a fresh counter, so the loop keeps going until one
lands.

--- init

use LWP::UserAgent;

my $ua = LWP::UserAgent->new(timeout => 10);

sub fail_23e { die "TEST 23e: $_[0]\n" }

# Every 10.x address carries a captcha decision, which is what lets this block use a
# fresh one per mint. Returns the HTTP status.
sub mint_as {
    my ($ip) = @_;
    my $req = HTTP::Request->new(GET => 'http://127.0.0.1:1984/t');
    $req->header('X-Forwarded-For' => $ip);
    my $resp = $ua->request($req);
    fail_23e("$ip: expected the widget or a ban, got HTTP " . $resp->code)
        unless ($resp->code == 200 && $resp->decoded_content =~ /<altcha-widget/)
            || $resp->code == 403;
    return $resp->code;
}

my $probe = $ua->get('http://127.0.0.1:1984/_budget');
fail_23e('/_budget: HTTP ' . $probe->code) unless $probe->is_success;
my $cap = $probe->decoded_content;
fail_23e("MintsPerSecond is '$cap', expected a number") unless $cap =~ /^\d+$/;

# At MAX_COST a derivation cannot be cheap. A cap in the thousands here would mean
# New() timed the clock rather than the KDF - the mistake that produced 16 ms for a
# single round while this was being written.
fail_23e("MintsPerSecond calibrated to $cap at ALTCHA_COST=100000, which is too high "
    . "for a derivation that expensive - New() has most likely mismeasured")
    unless $cap >= 1 && $cap <= 2000;

my ($served, $refused, $octet) = (0, 0, 0);
my $bound = $cap * 3 + 6;
while ($octet < $bound) {
    $octet++;
    my $code = mint_as("10.0.0.$octet");
    $code == 403 ? $refused++ : $served++;
    last if $refused > 0 && $served > 0;
}

fail_23e("$bound addresses each minted once and none was refused, with the budget at "
    . "$cap/s - nothing is bounding the aggregate")
    unless $refused > 0;
fail_23e("every one of $octet addresses was refused - the budget is refusing work it "
    . "has not been charged for")
    unless $served > 0;

# Expiry, on the real 2s init_ttl. A fresh address a couple of seconds later has to
# mint, or the counter is a latch rather than a per-second bucket.
sleep 3;
fail_23e("a fresh address was still refused 3s after the budget was spent - the "
    . "counter is not expiring")
    unless mint_as('10.9.9.9') == 200;

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
        local ok, err = cs.init("./t/conf_t/23e_altcha_mint_budget_crowdsec_nginx_bouncer.conf", "crowdsec-nginx-bouncer/v1.0.8")
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
            if args.ip ~= nil and args.ip:find("^10%.") ~= nil then
               ngx.say('[{"duration":"1h00m00s","id":4091593,"origin":"CAPI","scenario":"crowdsecurity/vpatch-CVE-2024-4577","scope":"Ip","type":"captcha","value":"' .. args.ip .. '"}]')
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

# Reached without an X-Forwarded-For, so it arrives as 127.0.0.1 and the LAPI stub
# declines to bounce it.
location = /_budget {
    content_by_lua_block {
        ngx.print(require("plugins.crowdsec.altcha").MintsPerSecond)
    }
}

--- more_headers
X-Forwarded-For: 10.9.9.9

--- request
GET /t

--- error_code: 200
--- response_body_like: <altcha-widget
--- error_log
altcha mint budget exhausted
--- no_error_log
altcha mint limit reached


=== TEST 23f: ALTCHA_MINTS_PER_SECOND replaces the calibrated budget

Exact mode. 23d and 23e cover what the cap does once it is reached; this block covers
only where the number comes from, because that is the part the setting changes.

ALTCHA_COST is 100 here, where a derivation costs a fraction of a millisecond and the
calibrated budget lands in the thousands. A cap of 3 therefore cannot be a measurement
that happened to agree - it can only be the configured rate. The startup line is
asserted alongside it, since it is what an operator reads to find out what share of a
worker the rate actually bought.

The rate is per worker and Test::Nginx runs one, so the configured rate and the
resulting cap are the same number here.

--- init

use LWP::UserAgent;

sub fail_23f { die "TEST 23f: $_[0]\n" }

my $ua = LWP::UserAgent->new;
my $probe = $ua->get('http://127.0.0.1:1984/_budget');
fail_23f('/_budget: HTTP ' . $probe->code) unless $probe->is_success;

my $cap = $probe->content;
fail_23f("MintsPerSecond is '$cap', expected a number") unless $cap =~ /^\d+$/;
fail_23f("MintsPerSecond is $cap with ALTCHA_MINTS_PER_SECOND=3 and one worker - the "
    . "configured rate is not reaching the cap, or the calibrated budget still is")
    unless $cap == 3;

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
        local ok, err = cs.init("./t/conf_t/23f_altcha_exact_mints_crowdsec_nginx_bouncer.conf", "crowdsec-nginx-bouncer/v1.0.8")
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
            if args.ip ~= nil and args.ip:find("^10%.") ~= nil then
               ngx.say('[{"duration":"1h00m00s","id":4091593,"origin":"CAPI","scenario":"crowdsecurity/vpatch-CVE-2024-4577","scope":"Ip","type":"captcha","value":"' .. args.ip .. '"}]')
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

location = /_budget {
    content_by_lua_block {
        ngx.print(require("plugins.crowdsec.altcha").MintsPerSecond)
    }
}

--- more_headers
X-Forwarded-For: 10.7.7.7

--- request
GET /t

--- error_code: 200
--- response_body_like: <altcha-widget
--- error_log
ALTCHA_MINTS_PER_SECOND=3 caps minting at 3 challenges per second


=== TEST 23g: a rate below one challenge per second is refused at startup

The floor is 1 rather than 0 because zero is not a bounded captcha, it is a stopped
one: every captcha decision would degrade for want of a challenge nobody is allowed to
mint. Refusing it at init says so once, in the log, instead of once per bounced
request.

Refused the way every other unusable captcha configuration is - captcha.New() returns
the error, the provider does not load, and decisions fall to FALLBACK_REMEDIATION. So
the address below is bounced with a ban, and the widget never appears.

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
        local ok, err = cs.init("./t/conf_t/23g_altcha_exact_mints_invalid_crowdsec_nginx_bouncer.conf", "crowdsec-nginx-bouncer/v1.0.8")
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
            if args.ip ~= nil and args.ip:find("^10%.") ~= nil then
               ngx.say('[{"duration":"1h00m00s","id":4091593,"origin":"CAPI","scenario":"crowdsecurity/vpatch-CVE-2024-4577","scope":"Ip","type":"captcha","value":"' .. args.ip .. '"}]')
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
X-Forwarded-For: 10.6.6.6

--- request
GET /t

--- error_code: 403
--- response_body_unlike: <altcha-widget
--- error_log eval
[
"ALTCHA_MINTS_PER_SECOND must be a finite number of challenges per worker per second",
"[Crowdsec] denied '10.6.6.6' with 'ban'",
]

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
# 60s verify window is spent on the work rather than on noticing a button
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

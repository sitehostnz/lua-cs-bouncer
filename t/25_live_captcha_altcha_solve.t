# Live mode, CAPTCHA_PROVIDER=altcha, solved for real.
#
# t/23 covers everything around the challenge - that it is issued, reused per IP,
# unique per IP, and that a payload for a challenge we never issued is refused. What
# it deliberately does not cover is the one property all of that rests on: that a
# solution derived the way the widget derives it is actually accepted.
#
# That gap matters because it is invisible. If the server's derivation drifted from
# the widget's - the counter encoded little-endian, the key truncated outside the
# loop instead of inside, a keyLength mismatch - every assertion in t/23 would still
# pass while no visitor on earth could get through, and the only trace would be
# "Invalid captcha from" in the logs.
#
# So the solver here is written from altcha's protocol rather than from altcha.lua:
# PBKDF2-HMAC-SHA256 over nonce||uint32be(counter) with the published salt, walking
# the counter up from zero until the derived key's hex starts with keyPrefix. Perl's
# Digest::SHA has no pbkdf2, but with keyLength 32 and SHA-256 the derivation is a
# single PBKDF2 block, which is a few lines of hmac_sha256.
#
# ALTCHA_COST=10 and ALTCHA_COMPLEXITY=100 keep it to at most 100 cheap passes.

use Test::Nginx::Socket 'no_plan';

no_shuffle();
run_tests();

__DATA__

=== TEST 25: altcha challenge solved end to end

--- init

use LWP::UserAgent;
use Digest::SHA qw(hmac_sha256);
use MIME::Base64 qw(encode_base64);

my $ua = LWP::UserAgent->new(timeout => 10);
my $url = 'http://127.0.0.1:1984/t';

open my $out_fh, '>', 't/servroot/logs/perl.init.log' or die $!;

sub fail {
    print $out_fh "$_[0]\n";
    exit 1;
}

# PBKDF2-HMAC-SHA256 with dkLen == 32. hLen is also 32, so there is exactly one
# block and the outer loop of RFC 2898 collapses away.
sub pbkdf2_sha256_32 {
    my ($password, $salt, $iterations) = @_;
    my $u = hmac_sha256($salt . pack('N', 1), $password);
    my $t = $u;
    for (2 .. $iterations) {
        $u = hmac_sha256($u, $password);
        $t ^= $u;
    }
    return $t;
}

# --- take a challenge ------------------------------------------------------
my $req = HTTP::Request->new(GET => $url);
$req->header('X-Forwarded-For' => '3.3.3.3');
my $page = $ua->request($req);
fail("expected the captcha page, got HTTP " . $page->code) unless $page->code == 200;

my ($challenge) = $page->decoded_content =~ m{challenge='(\{[^']*\})'}
    or fail("no inline challenge on the widget");

my ($algorithm) = $challenge =~ m{"algorithm":"([^"]+)"};
my ($nonce_hex)  = $challenge =~ m{"nonce":"([0-9a-f]+)"};
my ($salt_hex)   = $challenge =~ m{"salt":"([0-9a-f]+)"};
my ($prefix_hex) = $challenge =~ m{"keyPrefix":"([0-9a-f]+)"};
my ($cost)       = $challenge =~ m{"cost":(\d+)};
my ($key_length) = $challenge =~ m{"keyLength":(\d+)};

fail("challenge is incomplete: $challenge")
    unless $nonce_hex && $salt_hex && $prefix_hex && $cost && $key_length;

# cjson escapes the forward slash on the way out, so compare against both forms
$algorithm =~ s{\\/}{/}g;
fail("solver only implements PBKDF2/SHA-256, challenge asked for $algorithm")
    unless $algorithm eq 'PBKDF2/SHA-256';
fail("solver assumes keyLength 32, challenge asked for $key_length")
    unless $key_length == 32;

# --- solve it --------------------------------------------------------------
my $nonce = pack('H*', $nonce_hex);
my $salt  = pack('H*', $salt_hex);

my ($counter, $derived_hex);
for my $n (0 .. 100) {
    my $hex = unpack('H*', pbkdf2_sha256_32($nonce . pack('N', $n), $salt, $cost));
    if (index($hex, $prefix_hex) == 0) {
        ($counter, $derived_hex) = ($n, $hex);
        last;
    }
}
fail("no counter in 0..100 reproduced keyPrefix $prefix_hex - the server's "
   . "derivation and altcha's protocol have diverged") unless defined $counter;

# The counter is drawn from the top half of ALTCHA_COMPLEXITY, so a correct
# implementation lands in 50..100. Finding it at 0 would mean the prefix matched
# something trivial rather than real work.
fail("counter $counter is outside the 50..100 range ALTCHA_COMPLEXITY=100 implies")
    if $counter < 50;

# --- redeem it -------------------------------------------------------------
# Shaped like the widget's own payload: the challenge echoed back, plus the solution.
# Only solution.derivedKey is read, but sending the rest keeps this honest.
my $payload = '{"challenge":' . $challenge . ',"solution":{"counter":' . $counter
            . ',"derivedKey":"' . $derived_hex . '","time":1}}';
my $b64 = encode_base64($payload, '');
(my $encoded = $b64) =~ s/([^A-Za-z0-9\-\._~])/sprintf('%%%02X', ord($1))/ge;

my $post = HTTP::Request->new(POST => $url);
$post->header('X-Forwarded-For' => '3.3.3.3');
$post->header('Content-Type' => 'application/x-www-form-urlencoded');
$post->content('altcha-response=' . $encoded);
my $solved = $ua->request($post);

# LWP does not follow redirects on POST, so the 302 is visible here.
fail("a correct solution was refused: HTTP " . $solved->code
   . " (expected 302 to the original URI)") unless $solved->code == 302;
fail("released to '" . ($solved->header('Location') // '') . "', expected /t")
    unless ($solved->header('Location') // '') =~ m{/t$};

# Replay the winning payload, and assert what actually happens rather than what it
# looks like it should. By this point the solve has written VALIDATED_STATE against
# 3.3.3.3 for CAPTCHA_EXPIRATION, so csmod.Allow() fails its VERIFY_STATE test, never
# reaches validateCaptcha(), and lets the request through to the origin. A second 302
# is therefore not the failure to watch for here - it is unreachable whatever
# altcha.Validate() does - which is why the dict probe below is what pins redemption,
# and this is a check that the release window behaves as documented.
my $replay = $ua->request($post);
fail("a replayed solution did not reach the origin: HTTP " . $replay->code)
    unless $replay->code == 200 && $replay->decoded_content =~ /PROTECTED/;

# A solve has to leave nothing behind in the altcha dict. The challenge entry going
# is what stops a spent solution being accepted once the IP is challenged again; the
# mint counter
# going is what stops an honest visitor being charged for solving. That third one is not decoration - the
# appsec path deletes the captcha state instead of storing a CAPTCHA_EXPIRATION
# window, and CAPTCHA_EXPIRATION can be set below CHALLENGE_TTL, so a visitor can
# legitimately be challenged many times inside one window. If solving did not refund
# the budget, eleven honest solves would ban them.
#
# Read straight out of the shared dict rather than inferred from behaviour: the IP is
# released for CAPTCHA_EXPIRATION at this point, so it cannot simply be challenged
# again to find out.
for my $prefix (qw(altcha_challenge_ altcha_mints_)) {
    my $key = $prefix . '3.3.3.3';
    my $probe = $ua->get("http://127.0.0.1:1984/_dict?key=$key");
    fail("could not read the altcha dict: HTTP " . $probe->code) unless $probe->is_success;
    fail("$key survived a successful solve: " . $probe->decoded_content)
        unless $probe->decoded_content =~ /^absent/;
}

print $out_fh "Solved at counter $counter, released, replay refused, dict clean.\n";
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
        local ok, err = cs.init("./t/conf_t/25_live_captcha_altcha_solve_crowdsec_nginx_bouncer.conf", "crowdsec-nginx-bouncer/v1.0.8")
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
            if args.ip == "3.3.3.3" then
               ngx.say('[{"duration":"1h00m00s","id":4091593,"origin":"CAPI","scenario":"crowdsecurity/vpatch-CVE-2024-4577","scope":"Ip","type":"captcha","value":"3.3.3.3"}]')
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

# Test-only white-box read of the altcha dict, so the init block can assert on what
# a solve left behind rather than inferring it. Excluded from bouncing in the config.
location = /_dict {
    content_by_lua_block {
        local key = ngx.req.get_uri_args()["key"]
        local v = ngx.shared.crowdsec_altcha:get(key)
        ngx.print(v == nil and "absent" or ("present:" .. tostring(v)))
    }
}

--- more_headers
X-Forwarded-For: 3.3.3.3

# Having solved it, the IP is released for CAPTCHA_EXPIRATION and reaches the
# protected content instead of the captcha page.
--- request
GET /t

--- error_code: 200
--- response_body: PROTECTED
--- grep_error_log eval
qr/solved the altcha captcha, releasing to '[^']*' for \d+s/
--- grep_error_log_out eval
qr/solved the altcha captcha, releasing to '\/t' for 3600s/


=== TEST 25b: the release URI never comes from the request

Where a solved visitor is released to is held in crowdsec_cache as captcha_<ip>. The
only two things that can ever put a value there are ngx.var.uri, on the GET that opened
the flow, and the literal "/" when the flow opened on a non-GET and there was nothing
recorded yet. Nothing the client sends reaches it.

Upstream took it from the Referer header on a non-GET, which made it an open redirect:
the value goes into a Location header on the next successful solve, so a crafted or
attacker-induced Referer sends the visitor off-site the instant they pass the check.

The non-GET path matters for a reason beyond that, which is why it does not simply
store ngx.var.uri: the captcha form posts to itself, so a *failed* solve arrives here as
a POST and would overwrite the entry. Preserving what is already recorded is what stops
a visitor who gets it wrong once being released to the wrong place when they get it
right.

Asserted by reading the dict directly through /_cache rather than by following a
redirect, because the value has to be wrong in the cache before it can be wrong in a
Location, and this way no solve is needed to see it.

The grep_error_log count at the end is the positive half: three "unusable release URI"
lines prove all three hostile paths reached Lua and each fired the guard, which is also
what settles whether LWP or nginx normalised the escapes away en route.

--- init

use LWP::UserAgent;

sub fail_25b {
    my ($msg) = @_;
    die "TEST 25b: $msg\n";
}

my $ua = LWP::UserAgent->new(timeout => 10);
$ua->max_redirect(0);

my $url = 'http://127.0.0.1:1984/t';

sub cached_uri_25b {
    my $r = $ua->get('http://127.0.0.1:1984/_cache?key=captcha_5.5.5.5');
    fail_25b("could not read crowdsec_cache: HTTP " . $r->code) unless $r->is_success;
    return $r->decoded_content;
}

# The GET that opens the flow records the page the visitor wanted.
my $get = HTTP::Request->new(GET => $url);
$get->header('X-Forwarded-For' => '5.5.5.5');
my $resp = $ua->request($get);
fail_25b("expected the captcha page, got HTTP " . $resp->code) unless $resp->code == 200;
fail_25b("expected the altcha widget on the captcha page")
    unless $resp->decoded_content =~ /<altcha-widget/;
fail_25b("the GET did not record /t: " . cached_uri_25b())
    unless cached_uri_25b() eq 'present:/t';

# A wrong answer is a POST that reaches the same store. Whatever Referer it carries,
# the recorded destination has to survive it unchanged.
sub post_with_referer {
    my ($referer) = @_;
    my $post = HTTP::Request->new(POST => $url);
    $post->header('X-Forwarded-For' => '5.5.5.5');
    $post->header('Referer'         => $referer) if defined $referer;
    $post->content_type('application/x-www-form-urlencoded');
    $post->content('altcha-response=not-a-solution');
    my $r = $ua->request($post);
    fail_25b("a POST with Referer '" . (defined $referer ? $referer : '(absent)')
           . "' returned HTTP " . $r->code . ", expected the captcha page")
        unless $r->code == 200;
    return cached_uri_25b();
}

for my $referer ('https://evil.example/steal',
                 '//evil.example/steal',
                 'http://127.0.0.1:1984//evil.example/steal',
                 'http://127.0.0.1:1984/\\evil.example/steal',
                 'http://127.0.0.1:1984/somewhere-else',
                 '') {
    my $got = post_with_referer($referer);
    fail_25b("Referer '$referer' changed the release URI to $got")
        unless $got eq 'present:/t';
}

# Including no Referer at all, which is what Referrer-Policy: no-referrer produces -
# upstream fell back to the POST endpoint here.
my $got = post_with_referer(undef);
fail_25b("an absent Referer changed the release URI to $got") unless $got eq 'present:/t';

# The other channel into the same value, and the one that survived two rounds of
# fixing the first: the request path. nginx percent-DECODES $uri, so /%5C... arrives
# as /\..., and a browser's URL parser treats a backslash as a solidus for special
# schemes - so that Location is read as //evil.example/x, off-origin, exactly what the
# Referer cases above are guarding against. %0d%0a decodes to bytes ngx.redirect()
# refuses outright, turning the response that releases the visitor into a 500.
#
# nginx collapses a real "//" itself, so the backslash is the shape that reaches Lua.
# The third case is length rather than shape. crowdsec_cache holds the decisions this
# bouncer enforces, and the entry's size is chosen by whoever sent the request: measured
# at 256 B of zone per bounced address for a 9-byte path against 8,325 B for an 8 kB one,
# so a long path buys 32x the dict per address. 600 bytes is just past MAX_RELEASE_URI,
# which is the boundary worth testing - a path that long is legal, reaches Lua intact,
# and has to be refused as a destination without costing the visitor access.
for my $path ('/%5Cevil.example/x', '/a%0d%0aX-Injected:%20yes', '/' . ('x' x 600)) {
    # Seed with a known-good path first, so 'present:/' afterwards means THIS iteration
    # wrote it. Without the reset the second case asserts a value the first already left
    # behind, and would pass just as well if its request never reached the store - which
    # is the failure mode that let the path channel survive two rounds of fixes.
    my $seed = HTTP::Request->new(GET => 'http://127.0.0.1:1984/wanted');
    $seed->header('X-Forwarded-For' => '5.5.5.5');
    $ua->request($seed);
    fail_25b("the /wanted seed did not take: " . cached_uri_25b())
        unless cached_uri_25b() eq 'present:/wanted';

    my $r = HTTP::Request->new(GET => 'http://127.0.0.1:1984' . $path);
    $r->header('X-Forwarded-For' => '5.5.5.5');
    my $resp = $ua->request($r);
    fail_25b("GET $path returned HTTP " . $resp->code . ", expected the captcha page")
        unless $resp->code == 200;
    my $seen = cached_uri_25b();
    fail_25b("hostile request path $path became the release URI: $seen")
        unless $seen eq 'present:/';
}

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
        local ok, err = cs.init("./t/conf_t/25_live_captcha_altcha_solve_crowdsec_nginx_bouncer.conf", "crowdsec-nginx-bouncer/v1.0.8")
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
            if args.ip == "5.5.5.5" then
               ngx.say('[{"duration":"1h00m00s","id":4091594,"origin":"CAPI","scenario":"crowdsecurity/vpatch-CVE-2024-4577","scope":"Ip","type":"captcha","value":"5.5.5.5"}]')
            else
               ngx.print('null')
            end
            }
      }
}

--- config

# Server level, not per-location: 25b drives requests at paths with no location of
# their own (a hostile URI is not a route), and realip has to apply to those too or the
# bouncer sees 127.0.0.1 and never bounces them.
set_real_ip_from 127.0.0.1;
real_ip_header   X-Forwarded-For;
real_ip_recursive on;

location = /t {
    set_real_ip_from 127.0.0.1;
    real_ip_header   X-Forwarded-For;
    real_ip_recursive on;
    content_by_lua_block {
        ngx.print("PROTECTED")
    }
}

location = /wanted {
    content_by_lua_block {
        ngx.print("WANTED")
    }
}

# Test-only white-box read of the decision cache, so the init block can assert on the
# stored release URI rather than inferring it from a redirect it has to solve to see.
location = /_cache {
    content_by_lua_block {
        local key = ngx.req.get_uri_args()["key"]
        local v = ngx.shared.crowdsec_cache:get(key)
        ngx.print(v == nil and "absent" or ("present:" .. tostring(v)))
    }
}

--- more_headers
X-Forwarded-For: 5.5.5.5

# Still unsolved, so still the captcha page, and the entry still holds /t - which is
# the whole point of the block above.
--- request
GET /t

--- error_code: 200
--- response_body_like: <altcha-widget
--- grep_error_log eval
qr/unusable release URI for '5\.5\.5\.5'/
--- grep_error_log_out eval
"unusable release URI for '5.5.5.5'\nunusable release URI for '5.5.5.5'\n" .
"unusable release URI for '5.5.5.5'\n"

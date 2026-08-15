# Live mode, CAPTCHA_PROVIDER=altcha, ALTCHA_ALGORITHM=SHA-256, solved for real.
#
# t/25 does this for PBKDF2/SHA-256. ALTCHA_ALGORITHM accepts six values, and they
# split across two branches of derive_key(): three go to one PBKDF2 call, three to an
# iterated digest chain. t/25 covers the first branch and refuses to run against
# anything else, so the second shipped with no end-to-end coverage at all.
#
# The branch is easy to get subtly wrong in ways nothing else would catch. It hashes
# salt||nonce||counter on the first round and the *previous key* on every round after;
# the key is truncated to keyLength inside the loop rather than at the end; and the
# round count is max(1, cost), not cost. Get any of those wrong and every assertion in
# t/23 still passes - a challenge is issued, it is reused per IP, it is unique per IP -
# while no visitor can ever solve it, and the only trace is "Invalid captcha from".
#
# SHA-512, not SHA-256, and that choice is the difference between this file working and
# only appearing to. SHA-256 produces exactly 32 bytes, which is exactly KEY_LENGTH, so
# `key:sub(1, KEY_LENGTH)` is the identity function and moving it out of the loop
# changes nothing an SHA-256 test could observe - the truncation, the most error-prone
# line in the branch, would go unasserted. SHA-512 produces 64 bytes, so the cut is
# real on every round and hashing the untruncated key gives a different answer
# immediately. The widget agrees: its worker reads `keyLength = 32` from the challenge
# parameters and slices each digest to it, whatever the algorithm.
#
# As in t/25 the solver is written from altcha's protocol rather than from altcha.lua,
# so a shared misreading of the spec cannot make both sides agree with each other and
# disagree with the widget.

use Test::Nginx::Socket 'no_plan';

run_tests();

__DATA__

=== TEST 26: altcha SHA-256 challenge solved end to end

--- init

use LWP::UserAgent;
use Digest::SHA qw(sha512);
use MIME::Base64 qw(encode_base64);

my $ua = LWP::UserAgent->new(timeout => 10);
my $url = 'http://127.0.0.1:1984/t';

open my $out_fh, '>', 't/servroot/logs/perl.init.log' or die $!;

sub fail {
    print $out_fh "$_[0]\n";
    exit 1;
}

# src/algorithms/sha.ts, as the widget's inline worker implements it: round one
# digests salt||password, every round after digests the previous key, and the key is
# cut to keyLength each time round rather than once at the end.
sub sha_chain {
    my ($salt, $password, $iterations, $key_length) = @_;
    my $data = $salt . $password;
    my $key;
    for (1 .. ($iterations < 1 ? 1 : $iterations)) {
        # The truncation is inside the loop, so round N+1 hashes 32 bytes and not the
        # full 64 the digest produced. That is the property this file exists to pin.
        $key = substr(sha512($data), 0, $key_length);
        $data = $key;
    }
    return $key;
}

# --- take a challenge ------------------------------------------------------
my $req = HTTP::Request->new(GET => $url);
$req->header('X-Forwarded-For' => '4.4.4.4');
my $page = $ua->request($req);
fail("expected the captcha page, got HTTP " . $page->code) unless $page->code == 200;

my ($challenge) = $page->decoded_content =~ m{challenge='(\{[^']*\})'}
    or fail("no inline challenge on the widget");

my ($algorithm)  = $challenge =~ m{"algorithm":"([^"]+)"};
my ($nonce_hex)  = $challenge =~ m{"nonce":"([0-9a-f]+)"};
my ($salt_hex)   = $challenge =~ m{"salt":"([0-9a-f]+)"};
my ($prefix_hex) = $challenge =~ m{"keyPrefix":"([0-9a-f]+)"};
my ($cost)       = $challenge =~ m{"cost":(\d+)};
my ($key_length) = $challenge =~ m{"keyLength":(\d+)};

fail("challenge is incomplete: $challenge")
    unless $nonce_hex && $salt_hex && $prefix_hex && $cost && $key_length;

# The whole point of this file: if the config did not take, we would silently be
# re-testing the PBKDF2 path that t/25 already covers.
fail("expected the SHA-512 branch, challenge asked for $algorithm")
    unless $algorithm eq 'SHA-512';
# If keyLength ever stopped being shorter than the digest, the truncation would go
# back to being unobservable and this file would quietly stop testing it.
fail("keyLength is $key_length; SHA-512 digests 64 bytes, so this test only pins the "
   . "in-loop truncation while keyLength is smaller than that")
    unless $key_length == 32;

# --- solve it --------------------------------------------------------------
my $nonce = pack('H*', $nonce_hex);
my $salt  = pack('H*', $salt_hex);

my ($counter, $derived_hex);
for my $n (0 .. 100) {
    my $hex = unpack('H*', sha_chain($salt, $nonce . pack('N', $n), $cost, $key_length));
    if (index($hex, $prefix_hex) == 0) {
        ($counter, $derived_hex) = ($n, $hex);
        last;
    }
}
fail("no counter in 0..100 reproduced keyPrefix $prefix_hex - the server's SHA "
   . "derivation and altcha's protocol have diverged") unless defined $counter;

# Same range check as t/25: the counter is drawn from the top half, so finding it
# below 50 would mean the prefix matched something trivial rather than real work.
fail("counter $counter is outside the 50..100 range ALTCHA_COMPLEXITY=100 implies")
    if $counter < 50;

# --- redeem it -------------------------------------------------------------
my $payload = '{"challenge":' . $challenge . ',"solution":{"counter":' . $counter
            . ',"derivedKey":"' . $derived_hex . '","time":1}}';
my $b64 = encode_base64($payload, '');
(my $encoded = $b64) =~ s/([^A-Za-z0-9\-\._~])/sprintf('%%%02X', ord($1))/ge;

my $post = HTTP::Request->new(POST => $url);
$post->header('X-Forwarded-For' => '4.4.4.4');
$post->header('Content-Type' => 'application/x-www-form-urlencoded');
$post->content('altcha-response=' . $encoded);
my $solved = $ua->request($post);

fail("a correct SHA-256 solution was refused: HTTP " . $solved->code
   . " (expected 302 to the original URI)") unless $solved->code == 302;
fail("released to '" . ($solved->header('Location') // '') . "', expected /t")
    unless ($solved->header('Location') // '') =~ m{/t$};

print $out_fh "Solved SHA-512 at counter $counter, released.\n";
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
        local ok, err = cs.init("./t/conf_t/26_live_captcha_altcha_sha_crowdsec_nginx_bouncer.conf", "crowdsec-nginx-bouncer/v1.0.8")
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
            if args.ip == "4.4.4.4" then
               ngx.say('[{"duration":"1h00m00s","id":4091593,"origin":"CAPI","scenario":"crowdsecurity/vpatch-CVE-2024-4577","scope":"Ip","type":"captcha","value":"4.4.4.4"}]')
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
X-Forwarded-For: 4.4.4.4

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

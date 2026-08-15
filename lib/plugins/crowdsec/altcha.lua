-- ALTCHA proof-of-work challenges, issued and verified inside nginx.
--
-- Every other provider this bouncer supports answers to somebody else: recaptcha,
-- hcaptcha and turnstile are third-party services, and altcha's own hosted
-- equivalent, Sentinel, is a licensed product. ALTCHA (https://altcha.org) in its
-- free form has no verification service at all - the site is expected to mint and
-- check its own challenges - so the whole exchange fits inside the worker that is
-- already handling the request.
--
-- Protocol (ALTCHA proof-of-work v2, as implemented by the widget's src/pow.ts):
-- we publish a nonce, a salt, a KDF cost and the first half of a key derived from
-- a counter we keep to ourselves. The browser walks counters up from zero, running
-- PBKDF2 over nonce||counter each time, until the derived key starts with the
-- published prefix, then submits the key it found.
--
-- We keep the whole derived key in a shared dict instead of signing the challenge.
-- That buys three things: verification is one string comparison rather than a KDF
-- pass, there is no need to reproduce altcha's canonical JSON byte for byte to
-- check an HMAC, and a challenge is inherently single-use because redeeming it
-- removes it. The cost is that a challenge is only valid on the worker set that
-- issued it, which matches how the bouncer already caches captcha state per node.
--
-- Outstanding challenges are keyed by client IP rather than by nonce. Minting one
-- costs a KDF pass, and the bouncer hands out a captcha page on every request from
-- a challenged IP, so keying by nonce would let anyone already being bounced turn
-- page reloads into arbitrary work for nginx. Keyed by IP, a visitor gets the same
-- challenge back for as long as it is outstanding.
--
-- A challenge is redeemed - removed - only when the answer was right. That is what
-- stops a solution being replayed, and it is the only thing redemption has to do.
-- Destroying it on a wrong answer instead would hand every client a way to clear
-- the entry, so the next page load found nothing outstanding and paid for a fresh
-- derivation.
--
-- Letting wrong answers accumulate is safe, and not for the reason it first appears.
-- The derived key is not a secret: nonce, salt and cost are all published in the
-- challenge, so the only thing withheld is the counter, drawn from about five
-- thousand values at the default ALTCHA_COMPLEXITY. Anyone can simply compute the
-- answer offline - that is the proof of work, and it is what we are asking for. So
-- there is nothing an attacker could learn by submitting guesses that solving would
-- not hand them faster, and a wrong attempt costs far less than the derivation it
-- replaced: a dict read and a fixed-length compare instead of a KDF pass. Not free -
-- the body is still base64-decoded and parsed first, and the captcha page is
-- re-rendered after - but cheaper than what it stands in for. MIN_COMPLEXITY keeps
-- the counter range wide; that range multiplied by ALTCHA_COST, rather than the
-- width of the key, is the quantity that matters.
--
-- One challenge is still shared by everyone behind a NAT. Surviving a wrong answer
-- is what makes that safe: a client submitting junk no longer destroys the
-- challenge its neighbours are part-way through solving. Telling those visitors
-- apart would need per-visitor state this bouncer deliberately does not keep.
--
-- MINT_PREFIX bounds what is left, and refusing to mint past the ceiling fails
-- closed. It is a backstop rather than the primary defence: a client that never
-- solves can force only one mint per window per worker, because the derivation runs
-- to completion without yielding - so requests queued behind it reuse the challenge
-- it writes - and the challenge it would have to clear shares this counter's
-- lifetime. Per worker rather than outright, because a burst spread across workers
-- can have several of them miss the lookup before any completes its write. Note it
-- is keyed on the exact address, so rotating source addresses is how the ceiling is
-- *evaded*, not reached - in practice the way to reach it is challenges being
-- evicted from a shared dict under pressure.

local cjson = require "cjson"
local digest = require "resty.openssl.digest"
local kdf = require "resty.openssl.kdf"
local random = require "resty.random"
local str = require "resty.string"

local M = {_TYPE='module', _NAME='altcha.funcs', _VERSION='1.0-0'}

-- The algorithms the widget can actually solve. Checked against the bundle we
-- load rather than the upstream source: altcha@3.2.1/dist/main/altcha.js
-- registers exactly these six. Argon2id and Scrypt ship in the package as
-- separate worker chunks but are not registered by that bundle and appear
-- nowhere in it, so a browser given one would never find a solver. They are
-- deliberately absent here rather than accepted and quietly unsolvable.
--
-- `kind` selects how a key is derived, mirroring the widget:
--   pbkdf2 - src/algorithms/pbkdf2.ts, one PBKDF2 pass of `cost` iterations
--   sha    - src/algorithms/sha.ts, `cost` rounds of digest over the previous key
local ALGORITHMS = {
    ["SHA-256"]        = { kind = "sha",    md = "sha256" },
    ["SHA-384"]        = { kind = "sha",    md = "sha384" },
    ["SHA-512"]        = { kind = "sha",    md = "sha512" },
    ["PBKDF2/SHA-256"] = { kind = "pbkdf2", md = "sha256" },
    ["PBKDF2/SHA-384"] = { kind = "pbkdf2", md = "sha384" },
    ["PBKDF2/SHA-512"] = { kind = "pbkdf2", md = "sha512" },
}

-- PBKDF2/SHA-256 is the default because it is the only combination measured on
-- both sides, and because SHA-NI accelerates it on any AMD since 2017 or Intel
-- since Ice Lake - a speedup the GPUs an attacker would use cannot access. On a
-- host without SHA-NI the ordering inverts and PBKDF2/SHA-512 is the cheaper of
-- the two; `grep sha_ni /proc/cpuinfo` settles which case a machine is in.
local DEFAULT_ALGORITHM = "PBKDF2/SHA-256"

-- Uniform across every algorithm: the SHA family truncates its digest to this,
-- which is what the widget does with keyLength.
local KEY_LENGTH = 32
-- altcha's own default: publish half the derived key, keep the rest as the proof
local KEY_PREFIX_BYTES = KEY_LENGTH / 2
local NONCE_BYTES = 16
local SALT_BYTES = 16

-- ALTCHA_COMPLEXITY is the top of the counter range. The browser walks counters
-- up from zero until one reproduces the published prefix, so the counter we pick
-- *is* the number of attempts it has to make. We draw it from the top half of the
-- range, matching altcha-lib's own example of randomInt(5_000, 10_000).
--
-- Deliberately one knob rather than a min and a max. The counter has to be
-- unpredictable: if it were fixed, a client would derive the key in a single pass
-- and skip the work entirely, so a config that let someone set min == max would
-- silently disable the proof of work. Deriving the floor keeps the range wide by
-- construction.
local DEFAULT_COMPLEXITY = 10000
-- Below this the range is too narrow to be worth guessing against.
local MIN_COMPLEXITY = 100
-- And above this nobody solves it. The counter is the visitor's attempt count, so an
-- extra zero produces a challenge that outruns the widget's 90 second timeout, and a
-- visitor who cannot finish is not merely delayed: each abandoned page eventually
-- lapses into a fresh mint, and the mint ceiling turns that into a ban.
--
-- A million is far past anything solvable at a sane cost, so this rejects typos
-- rather than configurations. It also keeps the arithmetic honest, which matters
-- more than it looks: be32() encodes the counter as counter % 2^32, and above that
-- the browser finds a match at the reduced value and submits a key that compares
-- equal - the proof of work silently collapses, with no error to notice. Staying
-- well under 2^31 also keeps random_counter()'s modulo from degenerating, which
-- would otherwise stop drawing from the top half of the range the way it promises.
local MAX_COMPLEXITY = 1000000

-- How long a challenge stays redeemable, and so how long the entry that makes it
-- single-use has to be retained. The low end of the 20 minutes to 1 hour altcha's
-- security notes recommend: the exchange normally completes in seconds, but a
-- browser throttles the workers of a backgrounded tab, and a visitor who wandered
-- off mid-challenge should not come back to a dead page.
local CHALLENGE_TTL = 1200

-- Two entries per outstanding challenge, both keyed by client IP: the JSON handed
-- to the widget, and the derived key that redeems it.
local CHALLENGE_PREFIX = "altcha_challenge_"
local KEY_PREFIX = "altcha_key_"
-- Derivations spent by one IP in the current window. Accumulates across mints, and
-- is cleared by a solve or by its own TTL, whichever comes first - so unlike the two
-- above it can outlive the challenge that created it, which is the point: a client
-- that clears the pair some other way still cannot clear this.
local MINT_PREFIX = "altcha_mints_"

-- How many derivations one IP may spend per CHALLENGE_TTL window before minting is
-- refused. A solve clears the counter, so this only accumulates across challenges
-- that were never redeemed: lapsed mid-solve, backgrounded tabs, stale reloads.
-- Clearing on success matters more than it looks - the appsec path deletes the
-- captcha state rather than storing a window, and CAPTCHA_EXPIRATION can be set
-- shorter than CHALLENGE_TTL, so an honest visitor can legitimately be challenged
-- many times inside one window. Charging them for it would turn a solvable captcha
-- into a ban.
--
-- Ten against the cost of being wrong: at ALTCHA_COST=5000 a derivation is well
-- under a millisecond, so this is a few milliseconds per IP per twenty minutes,
-- while an unbounded count is one blocking KDF pass per request on a worker that
-- cannot yield during it.
local MAX_MINTS_PER_WINDOW = 10

-- We pay one pass of ALTCHA_COST per captcha page served, synchronously, on a worker
-- that cannot yield partway through a derivation - so a mistyped cost is a self
-- inflicted stall rather than merely a slow page. At the 5000 default a derivation is
-- well under a millisecond; this ceiling keeps the worst case in the low tens.
--
-- That arithmetic is PBKDF2's, where the whole iteration count is spent inside one
-- native call. The SHA family spends it in a Lua loop instead - one FFI call into
-- final() and one into reset() per round - so the same number buys a fraction of the
-- work and a multiple of the overhead, and 100000 there would be 200000 FFI round
-- trips per mint on a worker that cannot yield. Hence a separate, lower ceiling.
local MAX_COST = 100000
local MAX_SHA_COST = 10000
-- Well below the ceiling, and worth warning about long before it: see M.New().
local SHA_COST_WARN = 1000

-- The default cost has to depend on the family, because the two spend the number so
-- differently that one value cannot suit both. PBKDF2 hands its count to a single
-- native call; the SHA family runs that many sequential digests, awaited one at a
-- time in the browser and two FFI calls apiece here. 5000 is a fine PBKDF2 default
-- and a bad SHA one - past the widget's timeout on a modest phone, and tens of
-- milliseconds of blocking per mint on our side.
--
-- Picked here rather than in config.lua's default_values on purpose: a default set
-- there is indistinguishable from an operator's own value by the time it arrives,
-- so choosing per family would be impossible and every SHA user would be warned
-- about a number they never chose.
local DEFAULT_COST = 5000
-- altcha's own SHA examples sit in the low hundreds.
local DEFAULT_SHA_COST = 300

-- ALTCHA_COST: work per attempt. Paid once by us when minting, and `counter`
-- times by the visitor, so raising it raises both sides in step.
M.Cost = DEFAULT_COST
-- ALTCHA_COMPLEXITY: number of attempts. Paid only by the visitor - we still do
-- exactly one derivation - so this is the difficulty dial that is free for us.
M.Complexity = DEFAULT_COMPLEXITY
M.Algorithm = DEFAULT_ALGORITHM

--- Shared dict holding issued challenges.
-- A dedicated dict keeps a burst of captcha pages from evicting CrowdSec's own
-- decision cache, but fall back to that cache so the module still works against
-- an nginx config that predates the dedicated dict.
local function store()
    return ngx.shared.crowdsec_altcha or ngx.shared.crowdsec_cache
end

--- Big-endian uint32, the counter encoding altcha uses by default ('uint32' mode).
-- Written with arithmetic rather than bit operations so it behaves the same under
-- plain Lua 5.1 and LuaJIT.
local function be32(n)
    return string.char(
        math.floor(n / 16777216) % 256,
        math.floor(n / 65536) % 256,
        math.floor(n / 256) % 256,
        n % 256
    )
end

local function random_bytes(length)
    local bytes = random.bytes(length, true)
    if bytes == nil then
        return nil, "no strong entropy available for " .. length .. " random bytes"
    end
    return bytes, nil
end

--- Picks the counter the browser has to find, from the top half of the range.
-- It has to be unpredictable: a client that can guess it derives the key in a
-- single pass and skips the proof of work entirely. The modulo bias from folding
-- a 32-bit draw into the range is far too small to help with that.
local function random_counter()
    local bytes, err = random_bytes(4)
    if bytes == nil then
        return nil, err
    end
    local n = 0
    for i = 1, 4 do
        n = n * 256 + bytes:byte(i)
    end
    local floor = math.floor(M.Complexity / 2)
    return floor + (n % (M.Complexity - floor + 1)), nil
end

--- Derives the key for one counter value, exactly as the widget would.
-- Both branches have to match their counterpart in the altcha bundle byte for
-- byte, or the browser's answer will never equal ours.
local function derive_key(nonce, salt, counter)
    local spec = ALGORITHMS[M.Algorithm]
    local password = nonce .. be32(counter)

    if spec.kind == "pbkdf2" then
        local key, err = kdf.derive({
            type = kdf.PBKDF2,
            md = spec.md,
            salt = salt,
            pass = password,
            pbkdf2_iter = M.Cost,
            outlen = KEY_LENGTH,
        })
        if key == nil then
            return nil, M.Algorithm .. " failed: " .. tostring(err)
        end
        return key, nil
    end

    -- src/algorithms/sha.ts: an iterated digest chain. The first round hashes
    -- salt||password, every round after hashes the previous key - and it hashes
    -- the *truncated* key, so the truncation has to happen inside the loop.
    local d, err = digest.new(spec.md)
    if d == nil then
        return nil, M.Algorithm .. " failed: " .. tostring(err)
    end

    local data = salt .. password
    local key
    for _ = 1, math.max(1, M.Cost) do
        key, err = d:final(data)
        if key == nil then
            return nil, M.Algorithm .. " failed: " .. tostring(err)
        end
        key = key:sub(1, KEY_LENGTH)
        -- one context reused across rounds; allocating per round costs more
        -- than the hashing does at low iteration counts
        d:reset()
        data = key
    end
    return key, nil
end

--- Compares without an early exit, so a wrong guess takes the same time as a
-- near-miss. Both sides are lowercase hex of the same length by this point.
local function equal(a, b)
    if #a ~= #b then
        return false
    end
    local differences = 0
    for i = 1, #a do
        if a:byte(i) ~= b:byte(i) then
            differences = differences + 1
        end
    end
    return differences == 0
end

--- Validates configuration. Returns an error string, or nil when usable.
function M.New(cost, algorithm, complexity)
    -- First, and unconditionally. Every check below can return, and a missing dict is
    -- the more consequential problem of the two - an operator with both a typo'd cost
    -- and no dedicated dict should not be told only about the typo. Not fatal itself:
    -- the fallback works, and refusing would take captcha away from an nginx config
    -- that predates the dedicated dict.
    if ngx.shared.crowdsec_altcha == nil then
        ngx.log(ngx.ERR, "no 'crowdsec_altcha' shared dict declared, falling back to " ..
            "'crowdsec_cache'. Add `lua_shared_dict crowdsec_altcha 10m;` to the nginx " ..
            "http block: outstanding challenges otherwise compete with CrowdSec's own " ..
            "decisions for that dict, and evicting them escalates captcha to ban.")
    end

    if algorithm ~= nil and algorithm ~= "" then
        if ALGORITHMS[algorithm] == nil then
            local supported = {}
            for name in pairs(ALGORITHMS) do supported[#supported+1] = name end
            table.sort(supported)
            return "unsupported ALTCHA_ALGORITHM '" .. tostring(algorithm) ..
                "', expected one of " .. table.concat(supported, ", ")
        end
        M.Algorithm = algorithm
    end

    if cost ~= nil and cost ~= "" then
        cost = tonumber(cost)
        if cost == nil or cost < 1 then
            return "ALTCHA_COST must be a positive number of rounds per attempt"
        end
        if cost > MAX_COST then
            return "ALTCHA_COST must be at most " .. MAX_COST ..
                ": we pay one pass of it per captcha page served, on a worker that " ..
                "cannot yield mid-derivation"
        end
        M.Cost = math.floor(cost)
    else
        -- Nothing configured, so the family picks. Reaching this branch at all is
        -- what tells us the operator did not choose the number, which is why
        -- ALTCHA_COST deliberately has no entry in config.lua's default_values.
        M.Cost = ALGORITHMS[M.Algorithm].kind == "sha" and DEFAULT_SHA_COST or DEFAULT_COST
    end

    -- The two families spend `cost` very differently. PBKDF2 hands it to one native
    -- call; the SHA family turns it into that many sequential awaited digests in the
    -- browser, and into that many pairs of FFI calls in derive_key() here, so the
    -- same number is far more expensive on both sides. MAX_COST is calibrated for
    -- PBKDF2 and is much too generous for this family, so refuse earlier.
    if ALGORITHMS[M.Algorithm].kind == "sha" and M.Cost > MAX_SHA_COST then
        return "ALTCHA_COST must be at most " .. MAX_SHA_COST .. " for " ..
            M.Algorithm .. ": this family spends the count in a loop rather than in " ..
            "one native call, so it costs two FFI round trips per round here, on a " ..
            "worker that cannot yield mid-derivation"
    end

    -- Below the ceiling but still high. altcha's own SHA examples sit in the low
    -- hundreds. Warn rather than refuse: where this actually bites depends on the
    -- visitor's device and on our own hardware, neither of which we can measure here.
    if ALGORITHMS[M.Algorithm].kind == "sha" and M.Cost > SHA_COST_WARN then
        ngx.log(ngx.ERR, "ALTCHA_COST=" .. M.Cost .. " is high for " .. M.Algorithm ..
            ": the SHA family runs that many sequential digests per attempt in the " ..
            "browser, and the widget gives up after 90s. It also lengthens the " ..
            "blocking derivation nginx performs per captcha page served. Values in " ..
            "the low hundreds suit this family; ALTCHA_COST is per-attempt work, " ..
            "ALTCHA_COMPLEXITY is the number of attempts.")
    end

    if complexity ~= nil and complexity ~= "" then
        complexity = tonumber(complexity)
        if complexity == nil or complexity < MIN_COMPLEXITY then
            return "ALTCHA_COMPLEXITY must be at least " .. MIN_COMPLEXITY ..
                ", below which the counter is too easy to guess"
        end
        if complexity > MAX_COMPLEXITY then
            return "ALTCHA_COMPLEXITY must be at most " .. MAX_COMPLEXITY ..
                ": it is the visitor's attempt count, and past this nobody finishes " ..
                "inside the widget's 90s timeout - a visitor who cannot finish is " ..
                "eventually banned rather than merely delayed"
        end
        M.Complexity = math.floor(complexity)
    end

    -- Fail at init rather than on the first bounced request. This also proves the
    -- shipped lua-resty-openssl can reach the chosen algorithm at all, which is
    -- worth checking per algorithm rather than once: they take different paths
    -- through the binding.
    local _, err = derive_key(string.rep("\0", NONCE_BYTES), string.rep("\0", SALT_BYTES), 0)
    if err ~= nil then
        return "altcha cannot derive keys, " .. err
    end

    return nil
end

--- Returns the challenge for one visitor, as the JSON the widget expects in its
-- `challenge` attribute, or nil plus an error.
-- An unsolved challenge already outstanding for this IP is handed back as-is, so
-- reloading the captcha page costs nothing. Minting a new one costs a PBKDF2 pass
-- at ALTCHA_COST, paid before the visitor has done any work, and is refused once
-- this IP has spent MAX_MINTS_PER_WINDOW of them.
function M.Challenge(ip)
    if type(ip) ~= "string" or ip == "" then
        return nil, "altcha challenges are keyed by client IP, and none was given"
    end

    local s = store()

    -- Both halves have to still be there. They are written and removed together, but
    -- they are two independent entries in the dict and eviction is per key, so one
    -- can outlive the other - and the reads here bias which one that is, since this
    -- promotes the challenge on every reload and never touches the key beside it.
    -- Handing back a challenge whose answer is gone would leave the visitor solving
    -- something that can no longer be redeemed.
    local outstanding = s:get(CHALLENGE_PREFIX .. ip)
    if outstanding ~= nil and s:get(KEY_PREFIX .. ip) ~= nil then
        return outstanding, nil
    end

    -- Counted before the work rather than after, so a derivation that fails still
    -- costs the caller its place in the window.
    local mints, err = s:incr(MINT_PREFIX .. ip, 1, 0, CHALLENGE_TTL)
    if mints == nil then
        return nil, "failed to count altcha challenges for " .. ip .. ": " .. tostring(err)
    end
    if mints > MAX_MINTS_PER_WINDOW then
        return nil, "altcha mint limit reached for " .. ip .. " (" ..
            MAX_MINTS_PER_WINDOW .. " per " .. CHALLENGE_TTL .. "s)"
    end

    local nonce, err = random_bytes(NONCE_BYTES)
    if nonce == nil then
        return nil, err
    end

    local salt, err = random_bytes(SALT_BYTES)
    if salt == nil then
        return nil, err
    end

    local counter, err = random_counter()
    if counter == nil then
        return nil, err
    end

    local key, err = derive_key(nonce, salt, counter)
    if key == nil then
        return nil, err
    end

    local key_hex = str.to_hex(key)

    local challenge = cjson.encode({
        parameters = {
            algorithm = M.Algorithm,
            cost = M.Cost,
            expiresAt = ngx.time() + CHALLENGE_TTL,
            keyLength = KEY_LENGTH,
            -- only the first half is published; the rest cannot be known without
            -- running the KDF at the right counter, which is the work being asked for
            keyPrefix = key_hex:sub(1, KEY_PREFIX_BYTES * 2),
            nonce = str.to_hex(nonce),
            salt = str.to_hex(salt),
        }
    })

    -- Key first: a challenge that got handed out without its answer being stored
    -- would be unsolvable, whereas an answer with no challenge beside it simply
    -- goes unused and expires.
    local ok, err, forcible = s:set(KEY_PREFIX .. ip, key_hex, CHALLENGE_TTL)
    if ok then
        -- keep the first write's `forcible`: it is the one that says the dict was
        -- full, and letting the second write's value replace it loses that warning
        -- whenever only the first had to evict something
        local ok2, err2, forcible2 = s:set(CHALLENGE_PREFIX .. ip, challenge, CHALLENGE_TTL)
        ok, err, forcible = ok2, err2, forcible or forcible2
    end
    if not ok then
        return nil, "failed to store altcha challenge: " .. tostring(err)
    end
    if forcible then
        ngx.log(ngx.ERR, "Lua shared dict (altcha challenges) is full, please increase dict size in config")
    end

    return challenge, nil
end

--- Checks a payload submitted by the widget.
-- Returns (valid, err). Unlike the providers that call out over HTTP, a failure
-- here is never a transient outage - there is nothing to be unreachable - so a
-- payload we cannot make sense of is simply not valid.
function M.Validate(payload, ip)
    if payload == nil or payload == "" then
        return false, nil
    end

    if type(ip) ~= "string" or ip == "" then
        return false, "altcha challenges are keyed by client IP, and none was given"
    end

    local raw = ngx.decode_base64(payload)
    if raw == nil then
        return false, "altcha payload is not valid base64"
    end

    local ok, decoded = pcall(cjson.decode, raw)
    if not ok or type(decoded) ~= "table" then
        return false, "altcha payload is not valid JSON"
    end

    local solution = decoded.solution
    if type(solution) ~= "table" or type(solution.derivedKey) ~= "string" then
        return false, "altcha payload carries no derived key"
    end

    -- Nothing in the payload is trusted to find the challenge: it is looked up by
    -- the IP we issued it to, so a caller cannot point the lookup somewhere else.
    local s = store()
    local expected = s:get(KEY_PREFIX .. ip)

    if expected == nil then
        -- Expired, never issued, or already spent - indistinguishable, and all
        -- mean the visitor has to take a fresh challenge.
        return false, nil
    end

    -- Length first, so an oversized derivedKey is rejected before :lower() copies it
    if #solution.derivedKey ~= #expected or
       not equal(expected, solution.derivedKey:lower()) then
        -- The challenge deliberately survives a wrong answer. Removing it here
        -- would let anyone destroy the challenge a neighbour behind the same NAT
        -- is part-way through solving, and would make the next page load pay for a
        -- fresh derivation - which is exactly the amplification the mint ceiling
        -- exists to bound. Unlimited wrong answers are affordable: this path is a
        -- dict read and a fixed-length compare, far cheaper than the derivation it
        -- replaced, and the answer being guessed at is one anybody can derive
        -- offline from the published nonce, salt and cost - so there is nothing
        -- here to learn that solving would not give up sooner.
        return false, nil
    end

    -- Redeem on success only. Removing the answer is what stops this solution
    -- being replayed - a second submission of the same payload finds nothing to
    -- compare against. The mint counter goes with it because a solve is proof the
    -- work was done, and should not be charged against the window: on the appsec
    -- path, and wherever CAPTCHA_EXPIRATION is shorter than CHALLENGE_TTL, an
    -- honest visitor is challenged again well inside it.
    s:delete(KEY_PREFIX .. ip)
    s:delete(CHALLENGE_PREFIX .. ip)
    s:delete(MINT_PREFIX .. ip)

    return true, nil
end

return M

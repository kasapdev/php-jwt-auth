<?php

declare(strict_types=1);

$__failures = 0;
function check(string $label, bool $condition): void
{
    global $__failures;
    echo ($condition ? "[PASS] " : "[FAIL] ") . $label . "\n";
    if (!$condition) {
        $__failures++;
    }
}

require_once __DIR__ . '/../src/JwtException.php';
require_once __DIR__ . '/../src/InvalidTokenException.php';
require_once __DIR__ . '/../src/InvalidSignatureException.php';
require_once __DIR__ . '/../src/InvalidClaimException.php';
require_once __DIR__ . '/../src/ExpiredTokenException.php';
require_once __DIR__ . '/../src/Base64Url.php';
require_once __DIR__ . '/../src/Jwt.php';

use Kasapdev\JwtAuth\Base64Url;
use Kasapdev\JwtAuth\ExpiredTokenException;
use Kasapdev\JwtAuth\InvalidClaimException;
use Kasapdev\JwtAuth\InvalidSignatureException;
use Kasapdev\JwtAuth\InvalidTokenException;
use Kasapdev\JwtAuth\Jwt;

// --- Base64Url helper ------------------------------------------------------------------

check('Base64Url encode strips padding and swaps chars', Base64Url::encode('any carnal pleasure.') === 'YW55IGNhcm5hbCBwbGVhc3VyZS4');
check('Base64Url round-trips arbitrary binary data', Base64Url::decode(Base64Url::encode("\xff\xfe\x00\x01binary")) === "\xff\xfe\x00\x01binary");
check('Base64Url encode never contains +, /, or =', !preg_match('/[+\/=]/', Base64Url::encode('some data !!! ???')));

$threw = false;
try {
    Base64Url::decode('not-valid-base64!!!!');
} catch (InvalidTokenException $e) {
    $threw = true;
}
check('Base64Url::decode throws InvalidTokenException on invalid input', $threw);

// --- HS256 encode/decode round trip -----------------------------------------------------

$secret = 'super-secret-key';
$payload = ['sub' => '1234567890', 'name' => 'Ada Lovelace', 'admin' => true];

$token = Jwt::encode($payload, $secret);
check('HS256 token has three dot-separated segments', count(explode('.', $token)) === 3);

$decoded = Jwt::decode($token, $secret);
check('HS256 decode recovers original payload', $decoded == $payload);

// header defaults
[$headerEncoded] = explode('.', $token);
$header = json_decode(Base64Url::decode($headerEncoded), true);
check('default header sets typ=JWT', $header['typ'] === 'JWT');
check('default header sets alg=HS256', $header['alg'] === 'HS256');

// custom header fields are preserved
$tokenWithKid = Jwt::encode($payload, $secret, 'HS256', ['kid' => 'key-1']);
[$headerEncoded2] = explode('.', $tokenWithKid);
$header2 = json_decode(Base64Url::decode($headerEncoded2), true);
check('custom header fields (kid) are preserved', $header2['kid'] === 'key-1');
check('custom header cannot override alg', $header2['alg'] === 'HS256');

// --- Wrong secret / tampered signature ----------------------------------------------------

$threw = false;
try {
    Jwt::decode($token, 'wrong-secret');
} catch (InvalidSignatureException $e) {
    $threw = true;
}
check('decoding with wrong secret throws InvalidSignatureException', $threw);

[$h, $p, $s] = explode('.', $token);
$tamperedPayload = Base64Url::encode(json_encode(['sub' => 'attacker', 'admin' => true]));
$tamperedToken = $h . '.' . $tamperedPayload . '.' . $s;

$threw = false;
try {
    Jwt::decode($tamperedToken, $secret);
} catch (InvalidSignatureException $e) {
    $threw = true;
}
check('tampering with the payload invalidates the signature', $threw);

// --- Malformed tokens --------------------------------------------------------------------

$threw = false;
try {
    Jwt::decode('not-a-jwt', $secret);
} catch (InvalidTokenException $e) {
    $threw = true;
}
check('token with wrong segment count throws InvalidTokenException', $threw);

$threw = false;
try {
    Jwt::decode('a.b', $secret);
} catch (InvalidTokenException $e) {
    $threw = true;
}
check('token with only two segments throws InvalidTokenException', $threw);

$threw = false;
try {
    Jwt::decode('!!!not-base64!!!.!!!not-base64!!!.sig', $secret);
} catch (InvalidTokenException $e) {
    $threw = true;
}
check('token with invalid base64url header throws InvalidTokenException', $threw);

$badJsonHeader = Base64Url::encode('{not valid json');
$threw = false;
try {
    Jwt::decode($badJsonHeader . '.' . $p . '.' . $s, $secret);
} catch (InvalidTokenException $e) {
    $threw = true;
}
check('token with invalid JSON header throws InvalidTokenException', $threw);

// --- Disallowed algorithm ------------------------------------------------------------------

$rs256LikeHeader = Base64Url::encode(json_encode(['typ' => 'JWT', 'alg' => 'RS256']));
$fakeToken = $rs256LikeHeader . '.' . $p . '.' . $s;
$threw = false;
try {
    Jwt::decode($fakeToken, $secret, ['HS256']);
} catch (InvalidTokenException $e) {
    $threw = true;
}
check('token using an algorithm outside allowedAlgos throws InvalidTokenException', $threw);

$threw = false;
try {
    Jwt::encode(['a' => 1], 'secret', 'NONE');
} catch (InvalidTokenException $e) {
    $threw = true;
}
check('encoding with an unsupported algorithm throws InvalidTokenException', $threw);

// --- exp / nbf claim validation -------------------------------------------------------------

$expiredToken = Jwt::encode(['sub' => '1', 'exp' => time() - 10], $secret);
$threw = false;
try {
    Jwt::decode($expiredToken, $secret);
} catch (ExpiredTokenException $e) {
    $threw = true;
}
check('expired token (exp in the past) throws ExpiredTokenException', $threw);

$validExpToken = Jwt::encode(['sub' => '1', 'exp' => time() + 3600], $secret);
$decoded = Jwt::decode($validExpToken, $secret);
check('token with future exp decodes successfully', $decoded['sub'] === '1');

$notYetValidToken = Jwt::encode(['sub' => '1', 'nbf' => time() + 3600], $secret);
$threw = false;
try {
    Jwt::decode($notYetValidToken, $secret);
} catch (ExpiredTokenException $e) {
    $threw = true;
}
check('token with future nbf throws ExpiredTokenException', $threw);

$nowValidNbfToken = Jwt::encode(['sub' => '1', 'nbf' => time() - 10], $secret);
$decoded = Jwt::decode($nowValidNbfToken, $secret);
check('token with past nbf decodes successfully', $decoded['sub'] === '1');

// --- RS256 --------------------------------------------------------------------------------

$rsaAvailable = function_exists('openssl_pkey_new');
$rsaKeyPair = null;
if ($rsaAvailable) {
    $rsaKeyPair = openssl_pkey_new([
        'private_key_bits' => 2048,
        'private_key_type' => OPENSSL_KEYTYPE_RSA,
    ]);
    $rsaAvailable = $rsaKeyPair !== false;
}

if ($rsaAvailable) {
    openssl_pkey_export($rsaKeyPair, $privateKeyPem);
    $details = openssl_pkey_get_details($rsaKeyPair);
    $publicKeyPem = $details['key'];

    $rsPayload = ['sub' => 'rs256-user', 'role' => 'admin'];
    $rsToken = Jwt::encode($rsPayload, $privateKeyPem, 'RS256');
    check('RS256 token has three segments', count(explode('.', $rsToken)) === 3);

    $rsDecoded = Jwt::decode($rsToken, $publicKeyPem, ['RS256']);
    check('RS256 decode with correct public key recovers payload', $rsDecoded == $rsPayload);

    // A different key pair must fail verification.
    $otherKeyPair = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
    $otherDetails = openssl_pkey_get_details($otherKeyPair);
    $otherPublicKeyPem = $otherDetails['key'];

    $threw = false;
    try {
        Jwt::decode($rsToken, $otherPublicKeyPem, ['RS256']);
    } catch (InvalidSignatureException $e) {
        $threw = true;
    }
    check('RS256 decode with the wrong public key throws InvalidSignatureException', $threw);
} else {
    echo "[SKIP] RS256 tests (openssl RSA key generation unavailable in this environment)\n";
}

// --- hash_equals is used for constant-time comparison (behavioral check) -------------------

// We can't directly measure timing safely in a unit test, but we can confirm that a
// signature differing only in the last byte is still correctly rejected (i.e. the
// comparison is a full, correct comparison and not a naive short-circuiting one that
// might exit early -- functionally verifying correctness of the comparison outcome).
[$h3, $p3, $s3] = explode('.', $token);
$rawSig = Base64Url::decode($s3);
$flippedLastByte = substr($rawSig, 0, -1) . chr(ord(substr($rawSig, -1)) ^ 0xFF);
$corruptedToken = $h3 . '.' . $p3 . '.' . Base64Url::encode($flippedLastByte);
$threw = false;
try {
    Jwt::decode($corruptedToken, $secret);
} catch (InvalidSignatureException $e) {
    $threw = true;
}
check('signature differing by a single bit is rejected', $threw);

// --- Header missing "alg" entirely --------------------------------------------------------

$noAlgHeader = Base64Url::encode(json_encode(['typ' => 'JWT']));
$threw = false;
try {
    Jwt::decode($noAlgHeader . '.' . $p . '.' . $s, $secret);
} catch (InvalidTokenException $e) {
    $threw = true;
}
check('token with a header missing "alg" entirely throws InvalidTokenException', $threw);

// --- Non-string "alg" in header ------------------------------------------------------------

$numericAlgHeader = Base64Url::encode(json_encode(['typ' => 'JWT', 'alg' => 256]));
$threw = false;
try {
    Jwt::decode($numericAlgHeader . '.' . $p . '.' . $s, $secret);
} catch (InvalidTokenException $e) {
    $threw = true;
}
check('token with a non-string "alg" header value throws InvalidTokenException', $threw);

// --- Payload that decodes to a JSON scalar, not an object ----------------------------------

$scalarPayloadToken = Jwt::encode(['x' => 1], $secret);
[$scalarHeader] = explode('.', $scalarPayloadToken);
$rawScalarPayload = Base64Url::encode('42');
// Re-sign so this failure is specifically about payload shape, not signature mismatch.
$reSignedInput = $scalarHeader . '.' . $rawScalarPayload;
$reSignature = Base64Url::encode(hash_hmac('sha256', $reSignedInput, $secret, true));
$scalarToken = $reSignedInput . '.' . $reSignature;

$threw = false;
try {
    Jwt::decode($scalarToken, $secret);
} catch (InvalidTokenException $e) {
    $threw = true;
}
check('token whose payload is a JSON scalar (not an object/array) throws InvalidTokenException', $threw);

// --- Non-numeric exp / nbf claims -----------------------------------------------------------

$badExpInput = $scalarHeader . '.' . Base64Url::encode(json_encode(['exp' => 'not-a-number']));
$badExpToken = $badExpInput . '.' . Base64Url::encode(hash_hmac('sha256', $badExpInput, $secret, true));
$threw = false;
try {
    Jwt::decode($badExpToken, $secret);
} catch (InvalidTokenException $e) {
    $threw = true;
}
check('non-numeric "exp" claim throws InvalidTokenException rather than being silently ignored', $threw);

$badNbfInput = $scalarHeader . '.' . Base64Url::encode(json_encode(['nbf' => 'not-a-number']));
$badNbfToken = $badNbfInput . '.' . Base64Url::encode(hash_hmac('sha256', $badNbfInput, $secret, true));
$threw = false;
try {
    Jwt::decode($badNbfToken, $secret);
} catch (InvalidTokenException $e) {
    $threw = true;
}
check('non-numeric "nbf" claim throws InvalidTokenException rather than being silently ignored', $threw);

// --- iss / aud claim validation --------------------------------------------------------------

$issuedToken = Jwt::encode(['sub' => '1', 'iss' => 'https://issuer.example', 'aud' => 'my-app'], $secret);

$decoded = Jwt::decode($issuedToken, $secret, ['HS256'], issuer: 'https://issuer.example');
check('decode with matching issuer succeeds', $decoded['sub'] === '1');

$threw = false;
try {
    Jwt::decode($issuedToken, $secret, ['HS256'], issuer: 'https://someone-else.example');
} catch (InvalidClaimException $e) {
    $threw = true;
}
check('decode with mismatched issuer throws InvalidClaimException', $threw);

$noIssToken = Jwt::encode(['sub' => '1'], $secret);
$threw = false;
try {
    Jwt::decode($noIssToken, $secret, ['HS256'], issuer: 'https://issuer.example');
} catch (InvalidClaimException $e) {
    $threw = true;
}
check('decode requiring an issuer throws InvalidClaimException when "iss" is absent', $threw);

$nonStringIssInput = $scalarHeader . '.' . Base64Url::encode(json_encode(['iss' => 42]));
$nonStringIssToken = $nonStringIssInput . '.' . Base64Url::encode(hash_hmac('sha256', $nonStringIssInput, $secret, true));
$threw = false;
try {
    Jwt::decode($nonStringIssToken, $secret, ['HS256'], issuer: 'https://issuer.example');
} catch (InvalidTokenException $e) {
    $threw = true;
}
check('non-string "iss" claim throws InvalidTokenException', $threw);

$decoded = Jwt::decode($issuedToken, $secret, ['HS256'], audience: 'my-app');
check('decode with matching string audience succeeds', $decoded['sub'] === '1');

$decoded = Jwt::decode($issuedToken, $secret, ['HS256'], audience: ['other-app', 'my-app']);
check('decode succeeds when audience list contains the expected value', $decoded['sub'] === '1');

$threw = false;
try {
    Jwt::decode($issuedToken, $secret, ['HS256'], audience: 'other-app');
} catch (InvalidClaimException $e) {
    $threw = true;
}
check('decode with mismatched audience throws InvalidClaimException', $threw);

$listAudToken = Jwt::encode(['sub' => '1', 'aud' => ['app-a', 'app-b']], $secret);
$decoded = Jwt::decode($listAudToken, $secret, ['HS256'], audience: 'app-b');
check('decode matches when token "aud" is an array containing the expected audience', $decoded['sub'] === '1');

$noAudToken = Jwt::encode(['sub' => '1'], $secret);
$threw = false;
try {
    Jwt::decode($noAudToken, $secret, ['HS256'], audience: 'my-app');
} catch (InvalidClaimException $e) {
    $threw = true;
}
check('decode requiring an audience throws InvalidClaimException when "aud" is absent', $threw);

$nonStringAudInput = $scalarHeader . '.' . Base64Url::encode(json_encode(['aud' => ['ok', 42]]));
$nonStringAudToken = $nonStringAudInput . '.' . Base64Url::encode(hash_hmac('sha256', $nonStringAudInput, $secret, true));
$threw = false;
try {
    Jwt::decode($nonStringAudToken, $secret, ['HS256'], audience: 'ok');
} catch (InvalidTokenException $e) {
    $threw = true;
}
check('"aud" array containing a non-string element throws InvalidTokenException', $threw);

$decoded = Jwt::decode($issuedToken, $secret, ['HS256'], issuer: 'https://issuer.example', audience: 'my-app');
check('decode with both issuer and audience matching succeeds', $decoded['sub'] === '1');

check(
    'decode without issuer/audience arguments is unaffected (backward compatible)',
    Jwt::decode($issuedToken, $secret)['sub'] === '1'
);

// --- Key rotation (decode against an array of candidate secrets) ---------------------------

$oldSecret = 'old-rotation-secret';
$newSecret = 'new-rotation-secret';
$rotationPayload = ['sub' => 'rotation-user', 'role' => 'member'];

$oldSignedToken = Jwt::encode($rotationPayload, $oldSecret);

$rotatedDecoded = Jwt::decode($oldSignedToken, [$newSecret, $oldSecret]);
check(
    'decode against [newSecret, oldSecret] verifies a token signed with the old secret and recovers its claims',
    $rotatedDecoded == $rotationPayload
);

$threw = false;
try {
    Jwt::decode($oldSignedToken, [$newSecret, 'some-other-secret']);
} catch (InvalidSignatureException $e) {
    $threw = true;
}
check(
    'decode against a candidate array that does not include the signing secret throws InvalidSignatureException',
    $threw
);

// A single string $secret must still behave exactly as before (backward compatibility).
$singleSecretDecoded = Jwt::decode($oldSignedToken, $oldSecret);
check('decode with a single string secret is unaffected by the array support', $singleSecretDecoded == $rotationPayload);

// The new secret alone (without the old one) must NOT decode an old token.
$threw = false;
try {
    Jwt::decode($oldSignedToken, $newSecret);
} catch (InvalidSignatureException $e) {
    $threw = true;
}
check('decode with only the new secret (old token, single string) throws InvalidSignatureException', $threw);

// --- Encoding RS256 with a malformed private key --------------------------------------------

$threw = false;
try {
    Jwt::encode(['a' => 1], 'this-is-not-a-pem-key', 'RS256');
} catch (InvalidTokenException $e) {
    $threw = true;
}
check('encoding RS256 with a malformed PEM key throws InvalidTokenException', $threw);

echo $__failures === 0 ? "\nAll tests passed.\n" : "\n$__failures test(s) FAILED.\n";
exit($__failures === 0 ? 0 : 1);

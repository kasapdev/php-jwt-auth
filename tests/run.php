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
require_once __DIR__ . '/../src/ExpiredTokenException.php';
require_once __DIR__ . '/../src/Base64Url.php';
require_once __DIR__ . '/../src/Jwt.php';

use Kasapdev\JwtAuth\Base64Url;
use Kasapdev\JwtAuth\ExpiredTokenException;
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

echo $__failures === 0 ? "\nAll tests passed.\n" : "\n$__failures test(s) FAILED.\n";
exit($__failures === 0 ? 0 : 1);

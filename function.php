<?php
function base32Decode($base32) {
    $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    $base32 = strtoupper($base32);
    $binaryString = '';

    for ($i = 0; $i < strlen($base32); $i++) {
        $currentChar = strpos($alphabet, $base32[$i]);
        $binaryString .= str_pad(decbin($currentChar), 5, '0', STR_PAD_LEFT);
    }

    $fiveBitBinaryArray = str_split($binaryString, 8);
    $decoded = '';

    foreach ($fiveBitBinaryArray as $bin) {
        if (strlen($bin) === 8) {
            $decoded .= chr(bindec($bin));
        }
    }

    return $decoded;
}

function OTP2fa($secret) {
    $timeStep = 30;
    $digits = 6;
    $timeOffset = 23;
    $key = base32Decode($secret);
    $time = floor((time() + $timeOffset) / $timeStep);

    // 8-byte zaman değeri
    $time = pack('N*', 0) . pack('N*', $time);

    // HMAC-SHA1 hesaplama
    $hash = hash_hmac('sha1', $time, $key, true);

    // Dinamik Truncation
    $offset = ord($hash[strlen($hash) - 1]) & 0xf;
    $otp = (
            ((ord($hash[$offset + 0]) & 0x7f) << 24) |
            ((ord($hash[$offset + 1]) & 0xff) << 16) |
            ((ord($hash[$offset + 2]) & 0xff) << 8) |
            (ord($hash[$offset + 3]) & 0xff)
        ) % pow(10, $digits);

    return str_pad($otp, $digits, '0', STR_PAD_LEFT);
}

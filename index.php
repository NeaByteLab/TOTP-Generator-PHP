<?php

/**
 * Generate OTP Secret
 * Params: $length
 */
function generateOtpSecret($length = 20) {
  $randomBytes = random_bytes($length);
  $base32Chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  $bits = '';
  $secret = '';
  foreach (str_split($randomBytes) as $byte) {
    $bits .= str_pad(decbin(ord($byte)), 8, '0', STR_PAD_LEFT);
  }
  for ($i = 0; $i < strlen($bits); $i += 5) {
    $chunk = substr($bits, $i, 5);
    if (strlen($chunk) < 5) {
      $chunk = str_pad($chunk, 5, '0', STR_PAD_RIGHT);
    }
    $index = bindec($chunk);
    $secret .= $base32Chars[$index % 32];
  }
  return $secret;
}

/**
 * Base32 Decode
 * Params: $input
 */
function base32Decode($input) {
  $map = array_flip(str_split('ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'));
  $bits = '';
  foreach (str_split($input) as $char) {
    $char = strtoupper($char);
    if (!isset($map[$char])) {
      continue;
    }
    $val = $map[$char];
    $bits .= str_pad(decbin($val), 5, '0', STR_PAD_LEFT);
  }
  $output = '';
  for ($i = 0; $i + 8 <= strlen($bits); $i += 8) {
    $output .= chr(bindec(substr($bits, $i, 8)));
  }
  return $output;
}

/**
 * Generate Token
 * Params: $secret, $time
 */
function generateToken($secret, $time) {
  $key = base32Decode($secret);
  $binaryTime = pack('N*', 0) . pack('N*', $time);
  $hash = hash_hmac('sha1', $binaryTime, $key, true);
  $offset = ord(substr($hash, -1)) & 0x0F;
  $part = substr($hash, $offset, 4);
  $value = unpack('N', $part)[1] & 0x7FFFFFFF;
  return str_pad($value % 1000000, 6, '0', STR_PAD_LEFT);
}

/**
 * Verify Token
 * Params: $secret, $userToken
 */
function verifyToken($secret, $userToken) {
  $time = floor(time() / 30);
  foreach ([-1, 0, 1] as $window) {
    if (generateToken($secret, $time + $window) === $userToken) {
      return true;
    }
  }
  return false;
}

/**
 * Display QR Code
 * Params: $url
 */
function displayQrCode($url) {
  system("qrencode -t ANSIUTF8 '" . escapeshellarg($url) . "'");
}

/**
 * Main Execution
 */
$secret = generateOtpSecret();
echo "Secret: $secret\n";
$otpUrl = "otpauth://totp/MyApp:user@example.com?secret=$secret&issuer=MyApp";
displayQrCode($otpUrl);
$token = generateToken($secret, floor(time() / 30));
echo "Token: $token\n";
$handle = fopen("php://stdin", "r");
$attempts = 0;
while ($attempts < 3) {
  echo "Enter OTP: ";
  $userInput = trim(fgets($handle));
  $userInputClean = preg_replace('/[^0-9]/', '', $userInput);
  if ($userInputClean === '') {
    echo " -> OTP Invalid\n";
    $attempts++;
    continue;
  }
  if (verifyToken($secret, $userInputClean)) {
    echo " -> OTP Valid\n";
    break;
  } else {
    echo " -> OTP Invalid\n";
    $attempts++;
  }
}
if ($attempts === 3) {
  echo " -> Max Attempts Reached\n";
}
fclose($handle);
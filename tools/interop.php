<?php
$in = json_decode(file_get_contents('php://stdin'), true);
function pem($b64) {
    return "-----BEGIN PUBLIC KEY-----\n" . chunk_split($b64, 64, "\n") . "-----END PUBLIC KEY-----\n";
}
$ec = openssl_pkey_get_public(pem($in['ec_spki']));
$rsa = openssl_pkey_get_public(pem($in['rsa_spki']));
$ecDet = openssl_pkey_get_details($ec);
$ok = openssl_verify($in['canonical'], base64_decode($in['sig']), $ec, OPENSSL_ALGO_SHA256);
$asset = random_bytes(32);
$wrapOk = openssl_public_encrypt($asset, $wrapped, $rsa, OPENSSL_PKCS1_OAEP_PADDING);
echo json_encode([
  'curve' => $ecDet['ec']['curve_name'] ?? null,
  'ec_type' => $ecDet['type'] ?? null,
  'rsa_bits' => (openssl_pkey_get_details($rsa)['bits'] ?? 0),
  'verify' => $ok,
  'wrap_ok' => $wrapOk,
  'asset' => base64_encode($asset),
  'wrapped' => base64_encode((string)$wrapped),
]);

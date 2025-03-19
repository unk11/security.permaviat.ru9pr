<?php
$SECRET_KEY = "cAtwalkKey";

// 1. Получаем все заголовки
$headers = getallheaders();

// 2. Проверяем, что заголовок 'X-Token' существует и не пуст
if (!isset($headers['X-Token']) || empty($headers['X-Token'])) {
    header("HTTP/1.0 403 Forbidden");
    exit;
}

// 3. Сохраняем токен в переменную
$token = $headers['X-Token'];

// 4. Разбиваем токен на три части (header.payload.signature)
$tokenParts = explode('.', $token);
if (count($tokenParts) !== 3) {
    header("HTTP/1.0 403 Forbidden");
    echo "Некорректный формат токена";
    exit;
}

$header_base64  = $tokenParts[0];
$payload_base64 = $tokenParts[1];
$signatureJWT   = $tokenParts[2];

// 5. Декодируем header, чтобы узнать алгоритм
$headerDecoded = base64_decode($header_base64);
$headerObj     = json_decode($headerDecoded);
if (!$headerObj || !isset($headerObj->alg)) {
    header("HTTP/1.0 403 Forbidden");
    echo "Ошибка декодирования заголовка или отсутствует alg";
    exit;
}

// 6. Генерируем новую подпись (header + payload)
$unsignedToken = $header_base64 . '.' . $payload_base64;
$signature     = base64_encode(hash_hmac($headerObj->alg, $unsignedToken, $SECRET_KEY));

// 7. Сравниваем подпись из токена и сгенерированную подпись
if ($signatureJWT === $signature) {
    header("HTTP/1.0 200 OK");
    echo "Доступ к API разрешён.";
} else {
    header("HTTP/1.0 401 Unauthorized");
    echo "Подпись JWT не совпадает.";
}

// 8. Если подпись совпадает, декодируем payload для извлечения данных пользователя
$payloadDecoded = base64_decode($payload_base64);
$payloadObj     = json_decode($payloadDecoded);


// Отправляем ответ в формате JSON с сообщением и данными пользователя
header("Content-Type: application/json");
http_response_code(200);
echo json_encode([
    "message"  => "Доступ к API разрешён.",
    "userData" => $payloadObj
]);
?>

<?php
    require_once("config.php");
    require_once("../security.permaviat.ru/settings/connect_datebase.php");

    # Генерируем секретный ключ
    $SECRET_KEY = "cAtwalkKey";

    if(!isset($_SERVER['PHP_AUTH_USER']) || empty($_SERVER['PHP_AUTH_USER'])) { header("HTTP/1.0 403 Forbidden"); exit; }
    if(!isset($_SERVER['PHP_AUTH_PW']) || empty($_SERVER['PHP_AUTH_PW'])) { header("HTTP/1.0 403 Forbidden"); exit; }

    # Получаем данные из хешированного заголовка
    $login = $_SERVER['PHP_AUTH_USER'];
    $password = $_SERVER['PHP_AUTH_PW'];

    $query_user = $mysqli->query("SELECT * FROM `users` WHERE `login` = '$login' AND `password` = '$password';");
    if($read_user = $query_user->fetch_assoc()) {
        # Создаем информацию как должна вычисляться JWT подпись
        $header = array("typ" => "JWT", "alg" => "sha256");
        # создаем полезные данные которые будут храниться в JWT
        $payload = array(
            "UserId" => $read_user['id'],
            "roll"   => $read_user['roll']
        );

        # Токен пользователя из header + payload
        $unsignedToken = base64_encode(json_encode($header)) . '.' . base64_encode(json_encode($payload));
        # создаем сигнатуру при помощи алгоритма указанного в header signature
        $signature = hash_hmac($header['alg'], $unsignedToken, $SECRET_KEY);

        $token = base64_encode(json_encode($header)).".".base64_encode(json_encode($payload)).".".base64_encode($signature);
        header("token: ".$token);
        header('Content-Type: application/json');
        echo json_encode(array("token" => $token));
    }
    else
        header("HTTP/1.0 401 Unauthorized");
?>
